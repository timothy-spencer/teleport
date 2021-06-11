/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/parse"

	"github.com/gravitational/configure/cstrings"
	"github.com/gravitational/trace"

	"github.com/pborman/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/vulcand/predicate"
)

// getExtendedAdminUserRules provides access to the default set of rules assigned to
// all users.
func getExtendedAdminUserRules(features modules.Features) []types.Rule {
	rules := []types.Rule{
		types.NewRule(types.KindRole, RW()),
		types.NewRule(types.KindAuthConnector, RW()),
		types.NewRule(types.KindSession, RO()),
		types.NewRule(types.KindTrustedCluster, RW()),
		types.NewRule(types.KindEvent, RO()),
		types.NewRule(types.KindUser, RW()),
		types.NewRule(types.KindToken, RW()),
	}

	if features.Cloud {
		rules = append(rules, types.NewRule(types.KindBilling, RW()))
	}

	return rules
}

// DefaultImplicitRules provides access to the default set of implicit rules
// assigned to all roles.
var DefaultImplicitRules = []types.Rule{
	types.NewRule(types.KindNode, RO()),
	types.NewRule(types.KindProxy, RO()),
	types.NewRule(types.KindAuthServer, RO()),
	types.NewRule(types.KindReverseTunnel, RO()),
	types.NewRule(types.KindCertAuthority, ReadNoSecrets()),
	types.NewRule(types.KindClusterAuthPreference, RO()),
	types.NewRule(types.KindClusterName, RO()),
	types.NewRule(types.KindSSHSession, RO()),
	types.NewRule(types.KindAppServer, RO()),
	types.NewRule(types.KindRemoteCluster, RO()),
	types.NewRule(types.KindKubeService, RO()),
	types.NewRule(types.KindDatabaseServer, RO()),
}

// DefaultCertAuthorityRules provides access the minimal set of resources
// needed for a certificate authority to function.
var DefaultCertAuthorityRules = []types.Rule{
	types.NewRule(types.KindSession, RO()),
	types.NewRule(types.KindNode, RO()),
	types.NewRule(types.KindAuthServer, RO()),
	types.NewRule(types.KindReverseTunnel, RO()),
	types.NewRule(types.KindCertAuthority, ReadNoSecrets()),
}

// ErrSessionMFARequired is returned by AccessChecker when access to a resource
// requires an MFA check.
var ErrSessionMFARequired = trace.AccessDenied("access to resource requires MFA")

// RoleNameForUser returns role name associated with a user.
func RoleNameForUser(name string) string {
	return "user:" + name
}

// RoleNameForCertAuthority returns role name associated with a certificate
// authority.
func RoleNameForCertAuthority(name string) string {
	return "ca:" + name
}

// NewAdminRole is the default admin role for all local users if another role
// is not explicitly assigned (this role applies to all users in OSS version).
func NewAdminRole() types.Role {
	adminRules := getExtendedAdminUserRules(modules.GetModules().Features())
	role := &types.RoleV4{
		Kind:    types.KindRole,
		Version: types.V3,
		Metadata: types.Metadata{
			Name:      teleport.AdminRoleName,
			Namespace: apidefaults.Namespace,
		},
		Spec: types.RoleSpecV4{
			Options: types.RoleOptions{
				CertificateFormat: constants.CertificateFormatStandard,
				MaxSessionTTL:     types.NewDuration(apidefaults.MaxCertDuration),
				PortForwarding:    types.NewBoolOption(true),
				ForwardAgent:      types.NewBool(true),
				BPF:               apidefaults.EnhancedEvents(),
			},
			Allow: types.RoleConditions{
				Namespaces:       []string{apidefaults.Namespace},
				NodeLabels:       types.Labels{types.Wildcard: []string{types.Wildcard}},
				AppLabels:        types.Labels{types.Wildcard: []string{types.Wildcard}},
				KubernetesLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
				DatabaseLabels:   types.Labels{types.Wildcard: []string{types.Wildcard}},
				DatabaseNames:    []string{teleport.TraitInternalDBNamesVariable},
				DatabaseUsers:    []string{teleport.TraitInternalDBUsersVariable},
				Rules:            adminRules,
			},
		},
	}
	role.SetLogins(Allow, []string{teleport.TraitInternalLoginsVariable, teleport.Root})
	role.SetKubeUsers(Allow, []string{teleport.TraitInternalKubeUsersVariable})
	role.SetKubeGroups(Allow, []string{teleport.TraitInternalKubeGroupsVariable})
	return role
}

// NewImplicitRole is the default implicit role that gets added to all
// RoleSets.
func NewImplicitRole() types.Role {
	return &types.RoleV4{
		Kind:    types.KindRole,
		Version: types.V3,
		Metadata: types.Metadata{
			Name:      constants.DefaultImplicitRole,
			Namespace: apidefaults.Namespace,
		},
		Spec: types.RoleSpecV4{
			Options: types.RoleOptions{
				MaxSessionTTL: types.MaxDuration(),
				// PortForwarding has to be set to false in the default-implicit-role
				// otherwise all roles will be allowed to forward ports (since we default
				// to true in the check).
				PortForwarding: types.NewBoolOption(false),
			},
			Allow: types.RoleConditions{
				Namespaces: []string{apidefaults.Namespace},
				Rules:      types.CopyRulesSlice(DefaultImplicitRules),
			},
		},
	}
}

// RoleForUser creates an admin role for a services.User.
func RoleForUser(u types.User) types.Role {
	return &types.RoleV4{
		Kind:    types.KindRole,
		Version: types.V3,
		Metadata: types.Metadata{
			Name:      RoleNameForUser(u.GetName()),
			Namespace: apidefaults.Namespace,
		},
		Spec: types.RoleSpecV4{
			Options: types.RoleOptions{
				CertificateFormat: constants.CertificateFormatStandard,
				MaxSessionTTL:     types.NewDuration(apidefaults.MaxCertDuration),
				PortForwarding:    types.NewBoolOption(true),
				ForwardAgent:      types.NewBool(true),
				BPF:               apidefaults.EnhancedEvents(),
			},
			Allow: types.RoleConditions{
				Namespaces:       []string{apidefaults.Namespace},
				NodeLabels:       types.Labels{types.Wildcard: []string{types.Wildcard}},
				AppLabels:        types.Labels{types.Wildcard: []string{types.Wildcard}},
				KubernetesLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
				DatabaseLabels:   types.Labels{types.Wildcard: []string{types.Wildcard}},
				Rules: []types.Rule{
					types.NewRule(types.KindRole, RW()),
					types.NewRule(types.KindAuthConnector, RW()),
					types.NewRule(types.KindSession, RO()),
					types.NewRule(types.KindTrustedCluster, RW()),
					types.NewRule(types.KindEvent, RO()),
					types.NewRule(types.KindClusterAuthPreference, RW()),
					types.NewRule(types.KindClusterNetworkingConfig, RW()),
					types.NewRule(types.KindSessionRecordingConfig, RW()),
				},
			},
		},
	}
}

// NewDowngradedOSSAdminRole is a role for enabling RBAC for open source users.
// This role overrides built in OSS "admin" role to have less privileges.
// DELETE IN (7.x)
func NewDowngradedOSSAdminRole() types.Role {
	role := &types.RoleV4{
		Kind:    types.KindRole,
		Version: types.V3,
		Metadata: types.Metadata{
			Name:      teleport.AdminRoleName,
			Namespace: apidefaults.Namespace,
			Labels:    map[string]string{teleport.OSSMigratedV6: types.True},
		},
		Spec: types.RoleSpecV4{
			Options: types.RoleOptions{
				CertificateFormat: constants.CertificateFormatStandard,
				MaxSessionTTL:     types.NewDuration(apidefaults.MaxCertDuration),
				PortForwarding:    types.NewBoolOption(true),
				ForwardAgent:      types.NewBool(true),
				BPF:               apidefaults.EnhancedEvents(),
			},
			Allow: types.RoleConditions{
				Namespaces:       []string{apidefaults.Namespace},
				NodeLabels:       types.Labels{types.Wildcard: []string{types.Wildcard}},
				AppLabels:        types.Labels{types.Wildcard: []string{types.Wildcard}},
				KubernetesLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
				DatabaseLabels:   types.Labels{types.Wildcard: []string{types.Wildcard}},
				DatabaseNames:    []string{teleport.TraitInternalDBNamesVariable},
				DatabaseUsers:    []string{teleport.TraitInternalDBUsersVariable},
				Rules: []types.Rule{
					types.NewRule(types.KindEvent, RO()),
					types.NewRule(types.KindSession, RO()),
				},
			},
		},
	}
	role.SetLogins(Allow, []string{teleport.TraitInternalLoginsVariable})
	role.SetKubeUsers(Allow, []string{teleport.TraitInternalKubeUsersVariable})
	role.SetKubeGroups(Allow, []string{teleport.TraitInternalKubeGroupsVariable})
	return role
}

// NewOSSGithubRole creates a role for enabling RBAC for open source Github users
func NewOSSGithubRole(logins []string, kubeUsers []string, kubeGroups []string) types.Role {
	role := &types.RoleV4{
		Kind:    types.KindRole,
		Version: types.V3,
		Metadata: types.Metadata{
			Name:      "github-" + uuid.New(),
			Namespace: apidefaults.Namespace,
		},
		Spec: types.RoleSpecV4{
			Options: types.RoleOptions{
				CertificateFormat: constants.CertificateFormatStandard,
				MaxSessionTTL:     types.NewDuration(apidefaults.MaxCertDuration),
				PortForwarding:    types.NewBoolOption(true),
				ForwardAgent:      types.NewBool(true),
				BPF:               apidefaults.EnhancedEvents(),
			},
			Allow: types.RoleConditions{
				Namespaces:       []string{apidefaults.Namespace},
				NodeLabels:       types.Labels{types.Wildcard: []string{types.Wildcard}},
				AppLabels:        types.Labels{types.Wildcard: []string{types.Wildcard}},
				KubernetesLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
				DatabaseLabels:   types.Labels{types.Wildcard: []string{types.Wildcard}},
				DatabaseNames:    []string{teleport.TraitInternalDBNamesVariable},
				DatabaseUsers:    []string{teleport.TraitInternalDBUsersVariable},
				Rules: []types.Rule{
					types.NewRule(types.KindEvent, RO()),
				},
			},
		},
	}
	role.SetLogins(Allow, logins)
	role.SetKubeUsers(Allow, kubeUsers)
	role.SetKubeGroups(Allow, kubeGroups)
	return role
}

// RoleForCertAuthority creates role using types.CertAuthority.
func RoleForCertAuthority(ca types.CertAuthority) types.Role {
	return &types.RoleV4{
		Kind:    types.KindRole,
		Version: types.V3,
		Metadata: types.Metadata{
			Name:      RoleNameForCertAuthority(ca.GetClusterName()),
			Namespace: apidefaults.Namespace,
		},
		Spec: types.RoleSpecV4{
			Options: types.RoleOptions{
				MaxSessionTTL: types.NewDuration(apidefaults.MaxCertDuration),
			},
			Allow: types.RoleConditions{
				Namespaces:       []string{apidefaults.Namespace},
				NodeLabels:       types.Labels{types.Wildcard: []string{types.Wildcard}},
				AppLabels:        types.Labels{types.Wildcard: []string{types.Wildcard}},
				KubernetesLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
				DatabaseLabels:   types.Labels{types.Wildcard: []string{types.Wildcard}},
				Rules:            types.CopyRulesSlice(DefaultCertAuthorityRules),
			},
		},
	}
}

// Access service manages roles and permissions
type Access interface {
	// GetRoles returns a list of roles
	GetRoles(ctx context.Context) ([]types.Role, error)

	// CreateRole creates a role
	CreateRole(role types.Role) error

	// UpsertRole creates or updates role
	UpsertRole(ctx context.Context, role types.Role) error

	// DeleteAllRoles deletes all roles
	DeleteAllRoles() error

	// GetRole returns role by name
	GetRole(ctx context.Context, name string) (types.Role, error)

	// DeleteRole deletes role by name
	DeleteRole(ctx context.Context, name string) error
}

const (
	// Allow is the set of conditions that allow access.
	Allow types.RoleConditionType = true
	// Deny is the set of conditions that prevent access.
	Deny types.RoleConditionType = false
)

// ValidateRole parses validates the role, and sets default values.
func ValidateRole(r types.Role) error {
	if err := r.CheckAndSetDefaults(); err != nil {
		return err
	}

	// if we find {{ or }} but the syntax is invalid, the role is invalid
	for _, condition := range []types.RoleConditionType{Allow, Deny} {
		for _, login := range r.GetLogins(condition) {
			if strings.Contains(login, "{{") || strings.Contains(login, "}}") {
				_, err := parse.NewExpression(login)
				if err != nil {
					return trace.BadParameter("invalid login found: %v", login)
				}
			}
		}
	}

	rules := append(r.GetRules(types.Allow), r.GetRules(types.Deny)...)
	for _, rule := range rules {
		if err := validateRule(rule); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// validateRule parses the where and action fields to validate the rule.
func validateRule(r types.Rule) error {
	if len(r.Where) != 0 {
		parser, err := NewWhereParser(&Context{})
		if err != nil {
			return trace.Wrap(err)
		}
		_, err = parser.Parse(r.Where)
		if err != nil {
			return trace.BadParameter("could not parse 'where' rule: %q, error: %v", r.Where, err)
		}
	}

	if len(r.Actions) != 0 {
		parser, err := NewActionsParser(&Context{})
		if err != nil {
			return trace.Wrap(err)
		}
		for i, action := range r.Actions {
			_, err = parser.Parse(action)
			if err != nil {
				return trace.BadParameter("could not parse action %v %q, error: %v", i, action, err)
			}
		}
	}
	return nil
}

// ApplyTraits applies the passed in traits to any variables within the role
// and returns itself.
func ApplyTraits(r types.Role, traits map[string][]string) types.Role {
	for _, condition := range []types.RoleConditionType{Allow, Deny} {
		inLogins := r.GetLogins(condition)

		var outLogins []string
		for _, login := range inLogins {
			variableValues, err := ApplyValueTraits(login, traits)
			if err != nil {
				if !trace.IsNotFound(err) {
					log.Debugf("Skipping login %v: %v.", login, err)
				}
				continue
			}

			// Filter out logins that come from variables that are not valid Unix logins.
			for _, variableValue := range variableValues {
				if !cstrings.IsValidUnixUser(variableValue) {
					log.Debugf("Skipping login %v, not a valid Unix login.", variableValue)
					continue
				}

				// A valid variable was found in the traits, append it to the list of logins.
				outLogins = append(outLogins, variableValue)
			}
		}

		r.SetLogins(condition, apiutils.Deduplicate(outLogins))

		// apply templates to kubernetes groups
		inKubeGroups := r.GetKubeGroups(condition)
		var outKubeGroups []string
		for _, group := range inKubeGroups {
			variableValues, err := ApplyValueTraits(group, traits)
			if err != nil {
				if !trace.IsNotFound(err) {
					log.Debugf("Skipping kube group %v: %v.", group, err)
				}
				continue
			}
			outKubeGroups = append(outKubeGroups, variableValues...)
		}
		r.SetKubeGroups(condition, apiutils.Deduplicate(outKubeGroups))

		// apply templates to kubernetes users
		inKubeUsers := r.GetKubeUsers(condition)
		var outKubeUsers []string
		for _, user := range inKubeUsers {
			variableValues, err := ApplyValueTraits(user, traits)
			if err != nil {
				if !trace.IsNotFound(err) {
					log.Debugf("Skipping kube user %v: %v.", user, err)
				}
				continue
			}
			outKubeUsers = append(outKubeUsers, variableValues...)
		}
		r.SetKubeUsers(condition, apiutils.Deduplicate(outKubeUsers))

		// apply templates to database names
		inDbNames := r.GetDatabaseNames(condition)
		var outDbNames []string
		for _, name := range inDbNames {
			variableValues, err := ApplyValueTraits(name, traits)
			if err != nil {
				if !trace.IsNotFound(err) {
					log.Debugf("Skipping database name %q: %v.", name, err)
				}
				continue
			}
			outDbNames = append(outDbNames, variableValues...)
		}
		r.SetDatabaseNames(condition, apiutils.Deduplicate(outDbNames))

		// apply templates to database users
		inDbUsers := r.GetDatabaseUsers(condition)
		var outDbUsers []string
		for _, user := range inDbUsers {
			variableValues, err := ApplyValueTraits(user, traits)
			if err != nil {
				if !trace.IsNotFound(err) {
					log.Debugf("Skipping database user %q: %v.", user, err)
				}
				continue
			}
			outDbUsers = append(outDbUsers, variableValues...)
		}
		r.SetDatabaseUsers(condition, apiutils.Deduplicate(outDbUsers))

		// apply templates to node labels
		inLabels := r.GetNodeLabels(condition)
		if inLabels != nil {
			r.SetNodeLabels(condition, applyLabelsTraits(inLabels, traits))
		}

		// apply templates to cluster labels
		inLabels = r.GetClusterLabels(condition)
		if inLabels != nil {
			r.SetClusterLabels(condition, applyLabelsTraits(inLabels, traits))
		}

		// apply templates to kube labels
		inLabels = r.GetKubernetesLabels(condition)
		if inLabels != nil {
			r.SetKubernetesLabels(condition, applyLabelsTraits(inLabels, traits))
		}

		// apply templates to app labels
		inLabels = r.GetAppLabels(condition)
		if inLabels != nil {
			r.SetAppLabels(condition, applyLabelsTraits(inLabels, traits))
		}

		// apply templates to database labels
		inLabels = r.GetDatabaseLabels(condition)
		if inLabels != nil {
			r.SetDatabaseLabels(condition, applyLabelsTraits(inLabels, traits))
		}

		// apply templates to impersonation conditions
		inCond := r.GetImpersonateConditions(condition)
		var outCond types.ImpersonateConditions
		for _, user := range inCond.Users {
			variableValues, err := ApplyValueTraits(user, traits)
			if err != nil {
				if !trace.IsNotFound(err) {
					log.WithError(err).Debugf("Skipping impersonate user %q.", user)
				}
				continue
			}
			outCond.Users = append(outCond.Users, variableValues...)
		}
		for _, role := range inCond.Roles {
			variableValues, err := ApplyValueTraits(role, traits)
			if err != nil {
				if !trace.IsNotFound(err) {
					log.WithError(err).Debugf("Skipping impersonate role %q.", role)
				}
				continue
			}
			outCond.Roles = append(outCond.Roles, variableValues...)
		}
		outCond.Users = apiutils.Deduplicate(outCond.Users)
		outCond.Roles = apiutils.Deduplicate(outCond.Roles)
		outCond.Where = inCond.Where
		r.SetImpersonateConditions(condition, outCond)
	}

	return r
}

// applyLabelsTraits interpolates variables based on the templates
// and traits from identity provider. For example:
//
// cluster_labels:
//   env: ['{{external.groups}}']
//
// and groups: ['admins', 'devs']
//
// will be interpolated to:
//
// cluster_labels:
//   env: ['admins', 'devs']
//
func applyLabelsTraits(inLabels types.Labels, traits map[string][]string) types.Labels {
	outLabels := make(types.Labels, len(inLabels))
	// every key will be mapped to the first value
	for key, vals := range inLabels {
		keyVars, err := ApplyValueTraits(key, traits)
		if err != nil {
			// empty key will not match anything
			log.Debugf("Setting empty node label pair %q -> %q: %v", key, vals, err)
			keyVars = []string{""}
		}

		var values []string
		for _, val := range vals {
			valVars, err := ApplyValueTraits(val, traits)
			if err != nil {
				log.Debugf("Setting empty node label value %q -> %q: %v", key, val, err)
				// empty value will not match anything
				valVars = []string{""}
			}
			values = append(values, valVars...)
		}
		outLabels[keyVars[0]] = apiutils.Deduplicate(values)
	}
	return outLabels
}

// ApplyValueTraits applies the passed in traits to the variable,
// returns BadParameter in case if referenced variable is unsupported,
// returns NotFound in case if referenced trait is missing,
// mapped list of values otherwise, the function guarantees to return
// at least one value in case if return value is nil
func ApplyValueTraits(val string, traits map[string][]string) ([]string, error) {
	// Extract the variable from the role variable.
	variable, err := parse.NewExpression(val)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// For internal traits, only internal.logins, internal.kubernetes_users and
	// internal.kubernetes_groups are supported at the moment.
	if variable.Namespace() == teleport.TraitInternalPrefix {
		switch variable.Name() {
		case teleport.TraitLogins, teleport.TraitKubeGroups, teleport.TraitKubeUsers, teleport.TraitDBNames, teleport.TraitDBUsers:
		default:
			return nil, trace.BadParameter("unsupported variable %q", variable.Name())
		}
	}

	// If the variable is not found in the traits, skip it.
	interpolated, err := variable.Interpolate(traits)
	if trace.IsNotFound(err) || len(interpolated) == 0 {
		return nil, trace.NotFound("variable %q not found in traits", variable.Name())
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return interpolated, nil
}

// ruleScore is a sorting score of the rule, the larger the score, the more
// specific the rule is
func ruleScore(r *types.Rule) int {
	score := 0
	// wildcard rules are less specific
	if apiutils.SliceContainsStr(r.Resources, types.Wildcard) {
		score -= 4
	} else if len(r.Resources) == 1 {
		// rules that match specific resource are more specific than
		// fields that match several resources
		score += 2
	}
	// rules that have wildcard verbs are less specific
	if apiutils.SliceContainsStr(r.Verbs, types.Wildcard) {
		score -= 2
	}
	// rules that supply 'where' or 'actions' are more specific
	// having 'where' or 'actions' is more important than
	// whether the rules are wildcard or not, so here we have +8 vs
	// -4 and -2 score penalty for wildcards in resources and verbs
	if len(r.Where) > 0 {
		score += 8
	}
	// rules featuring actions are more specific
	if len(r.Actions) > 0 {
		score += 8
	}
	return score
}

// CompareRuleScore returns true if the first rule is more specific than the other.
//
// * nRule matching wildcard resource is less specific
// than same rule matching specific resource.
// * Rule that has wildcard verbs is less specific
// than the same rules matching specific verb.
// * Rule that has where section is more specific
// than the same rule without where section.
// * Rule that has actions list is more specific than
// rule without actions list.
func CompareRuleScore(r *types.Rule, o *types.Rule) bool {
	return ruleScore(r) > ruleScore(o)
}

// RuleSet maps resource to a set of rules defined for it
type RuleSet map[string][]types.Rule

// MakeRuleSet creates a new rule set from a list
func MakeRuleSet(rules []types.Rule) RuleSet {
	set := make(RuleSet)
	for _, rule := range rules {
		for _, resource := range rule.Resources {
			set[resource] = append(set[resource], rule)
		}
	}
	for resource := range set {
		rules := set[resource]
		// sort rules by most specific rule, the rule that has actions
		// is more specific than the one that has no actions
		sort.Slice(rules, func(i, j int) bool {
			return CompareRuleScore(&rules[i], &rules[j])
		})
		set[resource] = rules
	}
	return set
}

// Match tests if the resource name and verb are in a given list of rules.
// More specific rules will be matched first. See Rule.IsMoreSpecificThan
// for exact specs on whether the rule is more or less specific.
//
// Specifying order solves the problem on having multiple rules, e.g. one wildcard
// rule can override more specific rules with 'where' sections that can have
// 'actions' lists with side effects that will not be triggered otherwise.
//
func (set RuleSet) Match(whereParser predicate.Parser, actionsParser predicate.Parser, resource string, verb string) (bool, error) {
	// empty set matches nothing
	if len(set) == 0 {
		return false, nil
	}

	// check for matching resource by name
	// the most specific rule should win
	rules := set[resource]
	for _, rule := range rules {
		match, err := matchesWhere(&rule, whereParser)
		if err != nil {
			return false, trace.Wrap(err)
		}
		if match && (rule.HasVerb(types.Wildcard) || rule.HasVerb(verb)) {
			if err := processActions(&rule, actionsParser); err != nil {
				return true, trace.Wrap(err)
			}
			return true, nil
		}
	}

	// check for wildcard resource matcher
	for _, rule := range set[types.Wildcard] {
		match, err := matchesWhere(&rule, whereParser)
		if err != nil {
			return false, trace.Wrap(err)
		}
		if match && (rule.HasVerb(types.Wildcard) || rule.HasVerb(verb)) {
			if err := processActions(&rule, actionsParser); err != nil {
				return true, trace.Wrap(err)
			}
			return true, nil
		}
	}

	return false, nil
}

// matchesWhere returns true if Where rule matches.
// Empty Where block always matches.
func matchesWhere(r *types.Rule, parser predicate.Parser) (bool, error) {
	if r.Where == "" {
		return true, nil
	}
	ifn, err := parser.Parse(r.Where)
	if err != nil {
		return false, trace.Wrap(err)
	}
	fn, ok := ifn.(predicate.BoolPredicate)
	if !ok {
		return false, trace.BadParameter("invalid predicate type for where expression: %v", r.Where)
	}
	return fn(), nil
}

// processActions processes actions specified for this rule
func processActions(r *types.Rule, parser predicate.Parser) error {
	for _, action := range r.Actions {
		ifn, err := parser.Parse(action)
		if err != nil {
			return trace.Wrap(err)
		}
		fn, ok := ifn.(predicate.BoolPredicate)
		if !ok {
			return trace.BadParameter("invalid predicate type for action expression: %v", action)
		}
		fn()
	}
	return nil
}

// Slice returns slice from a set
func (set RuleSet) Slice() []types.Rule {
	var out []types.Rule
	for _, rules := range set {
		out = append(out, rules...)
	}
	return out
}

// AccessChecker interface implements access checks for given role or role set
type AccessChecker interface {
	// HasRole checks if the checker includes the role
	HasRole(role string) bool

	// RoleNames returns a list of role names
	RoleNames() []string

	// CheckAccessToServer checks access to server.
	CheckAccessToServer(login string, server types.Server, mfa AccessMFAParams) error

	// CheckAccessToRemoteCluster checks access to remote cluster
	CheckAccessToRemoteCluster(cluster types.RemoteCluster) error

	// CheckAccessToRule checks access to a rule within a namespace.
	CheckAccessToRule(context RuleContext, namespace string, rule string, verb string, silent bool) error

	// CheckLoginDuration checks if role set can login up to given duration and
	// returns a combined list of allowed logins.
	CheckLoginDuration(ttl time.Duration) ([]string, error)

	// CheckKubeGroupsAndUsers check if role can login into kubernetes
	// and returns two lists of combined allowed groups and users
	CheckKubeGroupsAndUsers(ttl time.Duration, overrideTTL bool) (groups []string, users []string, err error)

	// AdjustSessionTTL will reduce the requested ttl to lowest max allowed TTL
	// for this role set, otherwise it returns ttl unchanged
	AdjustSessionTTL(ttl time.Duration) time.Duration

	// AdjustClientIdleTimeout adjusts requested idle timeout
	// to the lowest max allowed timeout, the most restrictive
	// option will be picked
	AdjustClientIdleTimeout(ttl time.Duration) time.Duration

	// AdjustDisconnectExpiredCert adjusts the value based on the role set
	// the most restrictive option will be picked
	AdjustDisconnectExpiredCert(disconnect bool) bool

	// CheckAgentForward checks if the role can request agent forward for this
	// user.
	CheckAgentForward(login string) error

	// CanForwardAgents returns true if this role set offers capability to forward
	// agents.
	CanForwardAgents() bool

	// CanPortForward returns true if this RoleSet can forward ports.
	CanPortForward() bool

	// MaybeCanReviewRequests attempts to guess if this RoleSet belongs
	// to a user who should be submitting access reviews. Because not all rolesets
	// are derived from statically assigned roles, this may return false positives.
	MaybeCanReviewRequests() bool

	// PermitX11Forwarding returns true if this RoleSet allows X11 Forwarding.
	PermitX11Forwarding() bool

	// CertificateFormat returns the most permissive certificate format in a
	// RoleSet.
	CertificateFormat() string

	// EnhancedRecordingSet returns a set of events that will be recorded
	// for enhanced session recording.
	EnhancedRecordingSet() map[string]bool

	// CheckAccessToApp checks access to an application.
	CheckAccessToApp(login string, app *types.App, mfa AccessMFAParams) error

	// CheckAccessToKubernetes checks access to a kubernetes cluster.
	CheckAccessToKubernetes(login string, app *types.KubernetesCluster, mfa AccessMFAParams) error

	// CheckDatabaseNamesAndUsers returns database names and users this role
	// is allowed to use.
	CheckDatabaseNamesAndUsers(ttl time.Duration, overrideTTL bool) (names []string, users []string, err error)

	// CheckAccessToDatabase checks whether a user has access to the provided
	// database server.
	CheckAccessToDatabase(server types.DatabaseServer, mfa AccessMFAParams, matchers ...RoleMatcher) error

	// CheckImpersonate checks whether current user is allowed to impersonate
	// users and roles
	CheckImpersonate(currentUser, impersonateUser types.User, impersonateRoles []types.Role) error

	// CanImpersonateSomeone returns true if this checker has any impersonation rules
	CanImpersonateSomeone() bool
}

// FromSpec returns new RoleSet created from spec
func FromSpec(name string, spec types.RoleSpecV4) (RoleSet, error) {
	role, err := types.NewRole(name, spec)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return NewRoleSet(role), nil
}

// RW is a shortcut that returns all verbs.
func RW() []string {
	return []string{types.VerbList, types.VerbCreate, types.VerbRead, types.VerbUpdate, types.VerbDelete}
}

// RO is a shortcut that returns read only verbs that provide access to secrets.
func RO() []string {
	return []string{types.VerbList, types.VerbRead}
}

// ReadNoSecrets is a shortcut that returns read only verbs that do not
// provide access to secrets.
func ReadNoSecrets() []string {
	return []string{types.VerbList, types.VerbReadNoSecrets}
}

// RoleGetter is an interface that defines GetRole method
type RoleGetter interface {
	// GetRole returns role by name
	GetRole(ctx context.Context, name string) (types.Role, error)
}

// ExtractFromCertificate will extract roles and traits from a *ssh.Certificate
// or from the backend if they do not exist in the certificate.
func ExtractFromCertificate(access UserGetter, cert *ssh.Certificate) ([]string, wrappers.Traits, error) {
	// For legacy certificates, fetch roles and traits from the services.User
	// object in the backend.
	if isFormatOld(cert) {
		u, err := access.GetUser(cert.KeyId, false)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
		log.Warnf("User %v using old style SSH certificate, fetching roles and traits "+
			"from backend. If the identity provider allows username changes, this can "+
			"potentially allow an attacker to change the role of the existing user. "+
			"It's recommended to upgrade to standard SSH certificates.", cert.KeyId)
		return u.GetRoles(), u.GetTraits(), nil
	}

	// Standard certificates have the roles and traits embedded in them.
	roles, err := ExtractRolesFromCert(cert)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	traits, err := ExtractTraitsFromCert(cert)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	return roles, traits, nil
}

// ExtractFromIdentity will extract roles and traits from the *x509.Certificate
// which Teleport passes along as a *tlsca.Identity. If roles and traits do not
// exist in the certificates, they are extracted from the backend.
func ExtractFromIdentity(access UserGetter, identity tlsca.Identity) ([]string, wrappers.Traits, error) {
	// For legacy certificates, fetch roles and traits from the services.User
	// object in the backend.
	if missingIdentity(identity) {
		u, err := access.GetUser(identity.Username, false)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}

		log.Warnf("Failed to find roles or traits in x509 identity for %v. Fetching	"+
			"from backend. If the identity provider allows username changes, this can "+
			"potentially allow an attacker to change the role of the existing user.",
			identity.Username)
		return u.GetRoles(), u.GetTraits(), nil
	}

	return identity.Groups, identity.Traits, nil
}

// FetchRoleList fetches roles by their names, applies the traits to role
// variables, and returns the list
func FetchRoleList(roleNames []string, access RoleGetter, traits map[string][]string) (RoleSet, error) {
	var roles []types.Role

	for _, roleName := range roleNames {
		role, err := access.GetRole(context.TODO(), roleName)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		roles = append(roles, ApplyTraits(role, traits))
	}

	return roles, nil
}

// FetchRoles fetches roles by their names, applies the traits to role
// variables, and returns the RoleSet. Adds runtime roles like the default
// implicit role to RoleSet.
func FetchRoles(roleNames []string, access RoleGetter, traits map[string][]string) (RoleSet, error) {
	roles, err := FetchRoleList(roleNames, access, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return NewRoleSet(roles...), nil
}

// isFormatOld returns true if roles and traits were not found in the
// *ssh.Certificate.
func isFormatOld(cert *ssh.Certificate) bool {
	_, hasRoles := cert.Extensions[teleport.CertExtensionTeleportRoles]
	_, hasTraits := cert.Extensions[teleport.CertExtensionTeleportTraits]

	if hasRoles || hasTraits {
		return false
	}
	return true
}

// missingIdentity returns true if the identity is missing or the identity
// has no roles or traits.
func missingIdentity(identity tlsca.Identity) bool {
	if len(identity.Groups) == 0 || len(identity.Traits) == 0 {
		return true
	}
	return false
}

// ExtractRolesFromCert extracts roles from certificate metadata extensions.
func ExtractRolesFromCert(cert *ssh.Certificate) ([]string, error) {
	data, ok := cert.Extensions[teleport.CertExtensionTeleportRoles]
	if !ok {
		return nil, trace.NotFound("no roles found")
	}
	return UnmarshalCertRoles(data)
}

// ExtractTraitsFromCert extracts traits from the certificate extensions.
func ExtractTraitsFromCert(cert *ssh.Certificate) (wrappers.Traits, error) {
	rawTraits, ok := cert.Extensions[teleport.CertExtensionTeleportTraits]
	if !ok {
		return nil, trace.NotFound("no traits found")
	}
	var traits wrappers.Traits
	err := wrappers.UnmarshalTraits([]byte(rawTraits), &traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return traits, nil
}

// NewRoleSet returns new RoleSet based on the roles
func NewRoleSet(roles ...types.Role) RoleSet {
	// unauthenticated Nop role should not have any privileges
	// by default, otherwise it is too permissive
	if len(roles) == 1 && roles[0].GetName() == string(types.RoleNop) {
		return roles
	}
	return append(roles, NewImplicitRole())
}

// RoleSet is a set of roles that implements access control functionality
type RoleSet []types.Role

// MatchNamespace returns true if given list of namespace matches
// target namespace, wildcard matches everything.
func MatchNamespace(selectors []string, namespace string) (bool, string) {
	for _, n := range selectors {
		if n == namespace || n == types.Wildcard {
			return true, "matched"
		}
	}
	return false, fmt.Sprintf("no match, role selectors %v, server namespace: %v", selectors, namespace)
}

// MatchLogin returns true if attempted login matches any of the logins.
func MatchLogin(selectors []string, login string) (bool, string) {
	for _, l := range selectors {
		if l == login {
			return true, "matched"
		}
	}
	return false, fmt.Sprintf("no match, role selectors %v, login: %v", selectors, login)
}

// MatchDatabaseName returns true if provided database name matches selectors.
func MatchDatabaseName(selectors []string, name string) (bool, string) {
	for _, n := range selectors {
		if n == name || n == types.Wildcard {
			return true, "matched"
		}
	}
	return false, fmt.Sprintf("no match, role selectors %v, database name: %v", selectors, name)
}

// MatchDatabaseUser returns true if provided database user matches selectors.
func MatchDatabaseUser(selectors []string, user string) (bool, string) {
	for _, u := range selectors {
		if u == user || u == types.Wildcard {
			return true, "matched"
		}
	}
	return false, fmt.Sprintf("no match, role selectors %v, database user: %v", selectors, user)
}

// MatchLabels matches selector against target. Empty selector matches
// nothing, wildcard matches everything.
func MatchLabels(selector types.Labels, target map[string]string) (bool, string, error) {
	// Empty selector matches nothing.
	if len(selector) == 0 {
		return false, "no match, empty selector", nil
	}

	// *: * matches everything even empty target set.
	selectorValues := selector[types.Wildcard]
	if len(selectorValues) == 1 && selectorValues[0] == types.Wildcard {
		return true, "matched", nil
	}

	// Perform full match.
	for key, selectorValues := range selector {
		targetVal, hasKey := target[key]

		if !hasKey {
			return false, fmt.Sprintf("no key match: '%v'", key), nil
		}

		if !apiutils.SliceContainsStr(selectorValues, types.Wildcard) {
			result, err := utils.SliceMatchesRegex(targetVal, selectorValues)
			if err != nil {
				return false, "", trace.Wrap(err)
			} else if !result {
				return false, fmt.Sprintf("no value match: got '%v' want: '%v'", targetVal, selectorValues), nil
			}
		}
	}

	return true, "matched", nil
}

// RoleNames returns a slice with role names. Removes runtime roles like
// the default implicit role.
func (set RoleSet) RoleNames() []string {
	out := make([]string, 0, len(set))
	for _, r := range set {
		if r.GetName() == constants.DefaultImplicitRole {
			continue
		}
		out = append(out, r.GetName())
	}
	return out
}

// HasRole checks if the role set has the role
func (set RoleSet) HasRole(role string) bool {
	for _, r := range set {
		if r.GetName() == role {
			return true
		}
	}
	return false
}

// WithoutImplicit returns this role set with default implicit role filtered out.
func (set RoleSet) WithoutImplicit() (out RoleSet) {
	for _, r := range set {
		if r.GetName() == constants.DefaultImplicitRole {
			continue
		}
		out = append(out, r)
	}
	return out
}

// AdjustSessionTTL will reduce the requested ttl to lowest max allowed TTL
// for this role set, otherwise it returns ttl unchanged
func (set RoleSet) AdjustSessionTTL(ttl time.Duration) time.Duration {
	for _, role := range set {
		maxSessionTTL := role.GetOptions().MaxSessionTTL.Value()
		if maxSessionTTL != 0 && ttl > maxSessionTTL {
			ttl = maxSessionTTL
		}
	}
	return ttl
}

// MaxConnections returns the maximum number of concurrent ssh connections
// allowed.  If MaxConnections is zero then no maximum was defined
// and the number of concurrent connections is unconstrained.
func (set RoleSet) MaxConnections() int64 {
	var mcs int64
	for _, role := range set {
		if m := role.GetOptions().MaxConnections; m != 0 && (m < mcs || mcs == 0) {
			mcs = m
		}
	}
	return mcs
}

// MaxSessions returns the maximum number of concurrent ssh sessions
// per connection.  If MaxSessions is zero then no maximum was defined
// and the number of sessions is unconstrained.
func (set RoleSet) MaxSessions() int64 {
	var ms int64
	for _, role := range set {
		if m := role.GetOptions().MaxSessions; m != 0 && (m < ms || ms == 0) {
			ms = m
		}
	}
	return ms
}

// AdjustClientIdleTimeout adjusts requested idle timeout
// to the lowest max allowed timeout, the most restrictive
// option will be picked, negative values will be assumed as 0
func (set RoleSet) AdjustClientIdleTimeout(timeout time.Duration) time.Duration {
	if timeout < 0 {
		timeout = 0
	}
	for _, role := range set {
		roleTimeout := role.GetOptions().ClientIdleTimeout
		// 0 means not set, so it can't be most restrictive, disregard it too
		if roleTimeout.Duration() <= 0 {
			continue
		}
		switch {
		// in case if timeout is 0, means that incoming value
		// does not restrict the idle timeout, pick any other value
		// set by the role
		case timeout == 0:
			timeout = roleTimeout.Duration()
		case roleTimeout.Duration() < timeout:
			timeout = roleTimeout.Duration()
		}
	}
	return timeout
}

// AdjustDisconnectExpiredCert adjusts the value based on the role set
// the most restrictive option will be picked
func (set RoleSet) AdjustDisconnectExpiredCert(disconnect bool) bool {
	for _, role := range set {
		if role.GetOptions().DisconnectExpiredCert.Value() {
			disconnect = true
		}
	}
	return disconnect
}

// CheckKubeGroupsAndUsers check if role can login into kubernetes
// and returns two lists of allowed groups and users
func (set RoleSet) CheckKubeGroupsAndUsers(ttl time.Duration, overrideTTL bool) ([]string, []string, error) {
	groups := make(map[string]struct{})
	users := make(map[string]struct{})
	var matchedTTL bool
	for _, role := range set {
		maxSessionTTL := role.GetOptions().MaxSessionTTL.Value()
		if overrideTTL || (ttl <= maxSessionTTL && maxSessionTTL != 0) {
			matchedTTL = true
			for _, group := range role.GetKubeGroups(Allow) {
				groups[group] = struct{}{}
			}
			for _, user := range role.GetKubeUsers(Allow) {
				users[user] = struct{}{}
			}
		}
	}
	for _, role := range set {
		for _, group := range role.GetKubeGroups(Deny) {
			delete(groups, group)
		}
		for _, user := range role.GetKubeUsers(Deny) {
			delete(users, user)
		}
	}
	if !matchedTTL {
		return nil, nil, trace.AccessDenied("this user cannot request kubernetes access for %v", ttl)
	}
	if len(groups) == 0 && len(users) == 0 {
		return nil, nil, trace.NotFound("this user cannot request kubernetes access, has no assigned groups or users")
	}
	return utils.StringsSliceFromSet(groups), utils.StringsSliceFromSet(users), nil
}

// CheckDatabaseNamesAndUsers checks if the role has any allowed database
// names or users.
func (set RoleSet) CheckDatabaseNamesAndUsers(ttl time.Duration, overrideTTL bool) ([]string, []string, error) {
	names := make(map[string]struct{})
	users := make(map[string]struct{})
	var matchedTTL bool
	for _, role := range set {
		maxSessionTTL := role.GetOptions().MaxSessionTTL.Value()
		if overrideTTL || (ttl <= maxSessionTTL && maxSessionTTL != 0) {
			matchedTTL = true
			for _, name := range role.GetDatabaseNames(Allow) {
				names[name] = struct{}{}
			}
			for _, user := range role.GetDatabaseUsers(Allow) {
				users[user] = struct{}{}
			}
		}
	}
	for _, role := range set {
		for _, name := range role.GetDatabaseNames(Deny) {
			delete(names, name)
		}
		for _, user := range role.GetDatabaseUsers(Deny) {
			delete(users, user)
		}
	}
	if !matchedTTL {
		return nil, nil, trace.AccessDenied("this user cannot request database access for %v", ttl)
	}
	if len(names) == 0 && len(users) == 0 {
		return nil, nil, trace.NotFound("this user cannot request database access, has no assigned database names or users")
	}
	return utils.StringsSliceFromSet(names), utils.StringsSliceFromSet(users), nil
}

// CheckLoginDuration checks if role set can login up to given duration and
// returns a combined list of allowed logins.
func (set RoleSet) CheckLoginDuration(ttl time.Duration) ([]string, error) {
	logins, matchedTTL := set.GetLoginsForTTL(ttl)
	if !matchedTTL {
		return nil, trace.AccessDenied("this user cannot request a certificate for %v", ttl)
	}

	if len(logins) == 0 && !set.hasPossibleLogins() {
		// user was deliberately configured to have no login capability,
		// but ssh certificates must contain at least one valid principal.
		// we add a single distinctive value which should be unique, and
		// will never be a valid unix login (due to leading '-').
		logins = []string{"-teleport-nologin-" + uuid.New()}
	}

	if len(logins) == 0 {
		return nil, trace.AccessDenied("this user cannot create SSH sessions, has no allowed logins")
	}

	return logins, nil
}

// GetLoginsForTTL collects all logins that are valid for the given TTL.  The matchedTTL
// value indicates whether the TTL is within scope of *any* role.  This helps to distinguish
// between TTLs which are categorically invalid, and TTLs which are theoretically valid
// but happen to grant no logins.
func (set RoleSet) GetLoginsForTTL(ttl time.Duration) (logins []string, matchedTTL bool) {
	for _, role := range set {
		maxSessionTTL := role.GetOptions().MaxSessionTTL.Value()
		if ttl <= maxSessionTTL && maxSessionTTL != 0 {
			matchedTTL = true
			logins = append(logins, role.GetLogins(Allow)...)
		}
	}
	return apiutils.Deduplicate(logins), matchedTTL
}

// CheckAccessToRemoteCluster checks if a role has access to remote cluster. Deny rules are
// checked first then allow rules. Access to a cluster is determined by
// namespaces, labels, and logins.
//
// Note, logging in this function only happens in debug mode, this is because
// adding logging to this function (which is called on every server returned
// by GetRemoteClusters) can slow down this function by 50x for large clusters!
func (set RoleSet) CheckAccessToRemoteCluster(rc types.RemoteCluster) error {
	if len(set) == 0 {
		return trace.AccessDenied("access to cluster denied")
	}

	var errs []error

	rcLabels := rc.GetMetadata().Labels

	// For backwards compatibility, if there is no role in the set with labels and the cluster
	// has no labels, assume that the role set has access to the cluster.
	usesLabels := false
	for _, role := range set {
		if len(role.GetClusterLabels(Allow)) != 0 || len(role.GetClusterLabels(Deny)) != 0 {
			usesLabels = true
			break
		}
	}

	if usesLabels == false && len(rcLabels) == 0 {
		if log.GetLevel() == log.DebugLevel {
			log.WithFields(log.Fields{
				trace.Component: teleport.ComponentRBAC,
			}).Debugf("Grant access to cluster %v - no role in %v uses cluster labels and the cluster is not labeled.",
				rc.GetName(), set.RoleNames())
		}
		return nil
	}

	// Check deny rules first: a single matching label from
	// the deny role set prohibits access.
	for _, role := range set {
		matchLabels, labelsMessage, err := MatchLabels(role.GetClusterLabels(Deny), rcLabels)
		if err != nil {
			return trace.Wrap(err)
		}
		if matchLabels {
			// This condition avoids formatting calls on large scale.
			if log.GetLevel() == log.DebugLevel {
				log.WithFields(log.Fields{
					trace.Component: teleport.ComponentRBAC,
				}).Debugf("Access to cluster %v denied, deny rule in %v matched; match(label=%v)",
					rc.GetName(), role.GetName(), labelsMessage)
			}
			return trace.AccessDenied("access to cluster denied")
		}
	}

	// Check allow rules: label has to match in any role in the role set to be granted access.
	for _, role := range set {
		matchLabels, labelsMessage, err := MatchLabels(role.GetClusterLabels(Allow), rcLabels)
		log.WithFields(log.Fields{
			trace.Component: teleport.ComponentRBAC,
		}).Debugf("Check access to role(%v) rc(%v, labels=%v) matchLabels=%v, msg=%v, err=%v allow=%v rcLabels=%v",
			role.GetName(), rc.GetName(), rcLabels, matchLabels, labelsMessage, err, role.GetClusterLabels(Allow), rcLabels)
		if err != nil {
			return trace.Wrap(err)
		}
		if matchLabels {
			return nil
		}
		if log.GetLevel() == log.DebugLevel {
			deniedError := trace.AccessDenied("role=%v, match(label=%v)",
				role.GetName(), labelsMessage)
			errs = append(errs, deniedError)
		}
	}

	if log.GetLevel() == log.DebugLevel {
		log.WithFields(log.Fields{
			trace.Component: teleport.ComponentRBAC,
		}).Debugf("Access to cluster %v denied, no allow rule matched; %v", rc.GetName(), errs)
	}
	return trace.AccessDenied("access to cluster denied")
}

func (set RoleSet) hasPossibleLogins() bool {
	for _, role := range set {
		if role.GetName() == constants.DefaultImplicitRole {
			continue
		}
		if len(role.GetLogins(Allow)) != 0 {
			return true
		}
	}
	return false
}

// CheckAccessToServer checks if a role has access to a node. Deny rules are
// checked first then allow rules. Access to a node is determined by
// namespaces, labels, and logins.
//
// Note, logging in this function only happens in debug mode, this is because
// adding logging to this function (which is called on every server returned
// by GetNodes) can slow down this function by 50x for large clusters!
func (set RoleSet) CheckAccessToServer(login string, s types.Server, mfa AccessMFAParams) error {
	if mfa.AlwaysRequired && !mfa.Verified {
		log.WithFields(log.Fields{
			trace.Component: teleport.ComponentRBAC,
		}).Debugf("Access to node %q denied, cluster requires per-session MFA", s.GetHostname())
		return ErrSessionMFARequired
	}
	var errs []error

	// Check deny rules first: a single matching namespace, label, or login from
	// the deny role set prohibits access.
	for _, role := range set {
		matchNamespace, namespaceMessage := MatchNamespace(role.GetNamespaces(Deny), s.GetNamespace())
		matchLabels, labelsMessage, err := MatchLabels(role.GetNodeLabels(Deny), s.GetAllLabels())
		if err != nil {
			return trace.Wrap(err)
		}
		matchLogin, loginMessage := MatchLogin(role.GetLogins(Deny), login)
		if matchNamespace && (matchLabels || matchLogin) {
			if log.GetLevel() == log.DebugLevel {
				log.WithFields(log.Fields{
					trace.Component: teleport.ComponentRBAC,
				}).Debugf("Access to node %v denied, deny rule in %v matched; match(namespace=%v, label=%v, login=%v)",
					s.GetHostname(), role.GetName(), namespaceMessage, labelsMessage, loginMessage)
			}
			return trace.AccessDenied("access to server denied")
		}
	}

	allowed := false
	// Check allow rules: namespace, label, and login have to all match in
	// one role in the role set to be granted access.
	for _, role := range set {
		matchNamespace, namespaceMessage := MatchNamespace(role.GetNamespaces(Allow), s.GetNamespace())
		matchLabels, labelsMessage, err := MatchLabels(role.GetNodeLabels(Allow), s.GetAllLabels())
		if err != nil {
			return trace.Wrap(err)
		}
		matchLogin, loginMessage := MatchLogin(role.GetLogins(Allow), login)
		if matchNamespace && matchLabels && matchLogin {
			if mfa.Verified {
				return nil
			}
			if role.GetOptions().RequireSessionMFA {
				log.WithFields(log.Fields{
					trace.Component: teleport.ComponentRBAC,
				}).Debugf("Access to node %q denied, role %q requires per-session MFA; match(namespace=%v, label=%v, login=%v)",
					s.GetHostname(), role.GetName(), namespaceMessage, labelsMessage, loginMessage)
				return ErrSessionMFARequired
			}
			// Check all remaining roles, even if we found a match.
			// RequireSessionMFA should be enforced when at least one role has
			// it.
			allowed = true
			continue
		}
		if log.GetLevel() == log.DebugLevel {
			deniedError := trace.AccessDenied("role=%v, match(namespace=%v, label=%v, login=%v)",
				role.GetName(), namespaceMessage, labelsMessage, loginMessage)
			errs = append(errs, deniedError)
		}
	}
	if allowed {
		return nil
	}

	if log.GetLevel() == log.DebugLevel {
		log.WithFields(log.Fields{
			trace.Component: teleport.ComponentRBAC,
		}).Debugf("Access to node %v denied, no allow rule matched; %v", s.GetHostname(), errs)
	}
	return trace.AccessDenied("access to server denied")
}

// CheckAccessToApp checks if a role has access to an application. Deny rules
// are checked first, then allow rules. Access to an application is determined by
// namespaces and labels.
func (set RoleSet) CheckAccessToApp(namespace string, app *types.App, mfa AccessMFAParams) error {
	if mfa.AlwaysRequired && !mfa.Verified {
		log.WithFields(log.Fields{
			trace.Component: teleport.ComponentRBAC,
		}).Debugf("Access to app %q denied, cluster requires per-session MFA", app.Name)
		return ErrSessionMFARequired
	}
	var errs []error

	// Check deny rules: a matching namespace and label in the deny section
	// prohibits access.
	for _, role := range set {
		matchNamespace, namespaceMessage := MatchNamespace(role.GetNamespaces(Deny), namespace)
		matchLabels, labelsMessage, err := MatchLabels(role.GetAppLabels(Deny), types.CombineLabels(app.StaticLabels, app.DynamicLabels))
		if err != nil {
			return trace.Wrap(err)
		}
		if matchNamespace && matchLabels {
			if log.GetLevel() == log.DebugLevel {
				log.WithFields(log.Fields{
					trace.Component: teleport.ComponentRBAC,
				}).Debugf("Access to app %v denied, deny rule in %v matched; match(namespace=%v, label=%v)",
					app.Name, role.GetName(), namespaceMessage, labelsMessage)
			}
			return trace.AccessDenied("access to app denied")
		}
	}

	allowed := false
	// Check allow rules: namespace and label both have to match to be granted access.
	for _, role := range set {
		matchNamespace, namespaceMessage := MatchNamespace(role.GetNamespaces(Allow), namespace)
		matchLabels, labelsMessage, err := MatchLabels(role.GetAppLabels(Allow), types.CombineLabels(app.StaticLabels, app.DynamicLabels))
		if err != nil {
			return trace.Wrap(err)
		}
		if matchNamespace && matchLabels {
			if mfa.Verified {
				return nil
			}
			if role.GetOptions().RequireSessionMFA {
				log.WithFields(log.Fields{
					trace.Component: teleport.ComponentRBAC,
				}).Debugf("Access to app %q denied, role %q requires per-session MFA; match(namespace=%v, label=%v)",
					app.Name, role.GetName(), namespaceMessage, labelsMessage)
				return ErrSessionMFARequired
			}
			// Check all remaining roles, even if we found a match.
			// RequireSessionMFA should be enforced when at least one role has
			// it.
			allowed = true
			continue
		}
		if log.GetLevel() == log.DebugLevel {
			deniedError := trace.AccessDenied("role=%v, match(namespace=%v, label=%v)",
				role.GetName(), namespaceMessage, labelsMessage)
			errs = append(errs, deniedError)
		}
	}
	if allowed {
		return nil
	}

	if log.GetLevel() == log.DebugLevel {
		log.WithFields(log.Fields{
			trace.Component: teleport.ComponentRBAC,
		}).Debugf("Access to app %v denied, no allow rule matched; %v", app.Name, errs)
	}
	return trace.AccessDenied("access to app denied")
}

// CheckAccessToKubernetes checks if a role has access to a kubernetes cluster.
// Deny rules are checked first, then allow rules. Access to a kubernetes
// cluster is determined by namespaces and labels.
func (set RoleSet) CheckAccessToKubernetes(namespace string, kube *types.KubernetesCluster, mfa AccessMFAParams) error {
	if mfa.AlwaysRequired && !mfa.Verified {
		log.WithFields(log.Fields{
			trace.Component: teleport.ComponentRBAC,
		}).Debugf("Access to kubernetes cluster %q denied, cluster requires per-session MFA", kube.Name)
		return ErrSessionMFARequired
	}
	var errs []error

	// Check deny rules: a matching namespace and label in the deny section
	// prohibits access.
	for _, role := range set {
		matchNamespace, namespaceMessage := MatchNamespace(role.GetNamespaces(Deny), namespace)
		matchLabels, labelsMessage, err := MatchLabels(role.GetKubernetesLabels(Deny), types.CombineLabels(kube.StaticLabels, kube.DynamicLabels))
		if err != nil {
			return trace.Wrap(err)
		}
		if matchNamespace && matchLabels {
			if log.GetLevel() == log.DebugLevel {
				log.WithFields(log.Fields{
					trace.Component: teleport.ComponentRBAC,
				}).Debugf("Access to kubernetes cluster %v denied, deny rule in %v matched; match(namespace=%v, label=%v)",
					kube.Name, role.GetName(), namespaceMessage, labelsMessage)
			}
			return trace.AccessDenied("access to kubernetes cluster denied")
		}
	}

	allowed := false
	// Check allow rules: namespace and label both have to match to be granted access.
	for _, role := range set {
		matchNamespace, namespaceMessage := MatchNamespace(role.GetNamespaces(Allow), namespace)
		matchLabels, labelsMessage, err := MatchLabels(role.GetKubernetesLabels(Allow), types.CombineLabels(kube.StaticLabels, kube.DynamicLabels))
		if err != nil {
			return trace.Wrap(err)
		}
		if matchNamespace && matchLabels {
			if mfa.Verified {
				return nil
			}
			if role.GetOptions().RequireSessionMFA {
				log.WithFields(log.Fields{
					trace.Component: teleport.ComponentRBAC,
				}).Debugf("Access to kubernetes cluster %q denied, role %q requires per-session MFA; match(namespace=%v, label=%v)",
					kube.Name, role.GetName(), namespaceMessage, labelsMessage)
				return ErrSessionMFARequired
			}
			// Check all remaining roles, even if we found a match.
			// RequireSessionMFA should be enforced when at least one role has
			// it.
			allowed = true
			continue
		}
		if log.GetLevel() == log.DebugLevel {
			deniedError := trace.AccessDenied("role=%v, match(namespace=%v, label=%v)",
				role.GetName(), namespaceMessage, labelsMessage)
			errs = append(errs, deniedError)
		}
	}
	if allowed {
		return nil
	}

	if log.GetLevel() == log.DebugLevel {
		log.WithFields(log.Fields{
			trace.Component: teleport.ComponentRBAC,
		}).Debugf("Access to kubernetes cluster %v denied, no allow rule matched; %v", kube.Name, errs)
	}
	return trace.AccessDenied("access to kubernetes cluster denied")
}

// CanImpersonateSomeone returns true if this checker has any impersonation rules
func (set RoleSet) CanImpersonateSomeone() bool {
	for _, role := range set {
		cond := role.GetImpersonateConditions(Allow)
		if !cond.IsEmpty() {
			return true
		}
	}
	return false
}

// CheckImpersonate returns nil if this role set can impersonate
// a user and their roles, returns AccessDenied otherwise
// CheckImpersonate checks whether current user is allowed to impersonate
// users and roles
func (set RoleSet) CheckImpersonate(currentUser, impersonateUser types.User, impersonateRoles []types.Role) error {
	ctx := &impersonateContext{
		user:            currentUser,
		impersonateUser: impersonateUser,
	}
	whereParser, err := newImpersonateWhereParser(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	// check deny: a single match on a deny rule prohibits access
	for _, role := range set {
		cond := role.GetImpersonateConditions(Deny)
		matched, err := matchDenyImpersonateCondition(cond, impersonateUser, impersonateRoles)
		if err != nil {
			return trace.Wrap(err)
		}
		if matched {
			return trace.AccessDenied("access denied to '%s' to impersonate user '%s' and roles '%s'", currentUser.GetName(), impersonateUser.GetName(), roleNames(impersonateRoles))
		}
	}

	// check allow: if matches, allow to impersonate
	for _, role := range set {
		cond := role.GetImpersonateConditions(Allow)
		matched, err := matchAllowImpersonateCondition(ctx, whereParser, cond, impersonateUser, impersonateRoles)
		if err != nil {
			return trace.Wrap(err)
		}
		if matched {
			return nil
		}
	}

	return trace.AccessDenied("access denied to '%s' to impersonate user '%s' and roles '%s'", currentUser.GetName(), impersonateUser.GetName(), roleNames(impersonateRoles))
}

func roleNames(roles []types.Role) string {
	out := make([]string, len(roles))
	for i := range roles {
		out[i] = roles[i].GetName()
	}
	return strings.Join(out, ", ")
}

// matchAllowImpersonateCondition matches impersonate condition,
// both user, role and where condition has to match
func matchAllowImpersonateCondition(ctx *impersonateContext, whereParser predicate.Parser, cond types.ImpersonateConditions, impersonateUser types.User, impersonateRoles []types.Role) (bool, error) {
	// an empty set matches nothing
	if len(cond.Users) == 0 && len(cond.Roles) == 0 {
		return false, nil
	}
	// should specify both roles and users, this condition is also verified on the role level
	if len(cond.Users) == 0 || len(cond.Roles) == 0 {
		return false, trace.BadParameter("the system does not support empty roles and users")
	}

	anyUser, err := parse.NewAnyMatcher(cond.Users)
	if err != nil {
		return false, trace.Wrap(err)
	}

	if !anyUser.Match(impersonateUser.GetName()) {
		return false, nil
	}

	anyRole, err := parse.NewAnyMatcher(cond.Roles)
	if err != nil {
		return false, trace.Wrap(err)
	}

	for _, impersonateRole := range impersonateRoles {
		if !anyRole.Match(impersonateRole.GetName()) {
			return false, nil
		}
		// TODO:
		// This set impersonateRole inside the ctx that is in turn used inside whereParser
		// which is created in CheckImpersonate above but is being used right below.
		// This is unfortunate interface of the parser, instead
		// parser should accept additional context as a first argument.
		ctx.impersonateRole = impersonateRole
		match, err := matchesImpersonateWhere(cond, whereParser)
		if err != nil {
			return false, trace.Wrap(err)
		}
		if !match {
			return false, nil
		}
	}

	return true, nil
}

// matchDenyImpersonateCondition matches impersonate condition,
// greedy is used for deny type rules, where any user or role can match
func matchDenyImpersonateCondition(cond types.ImpersonateConditions, impersonateUser types.User, impersonateRoles []types.Role) (bool, error) {
	// an empty set matches nothing
	if len(cond.Users) == 0 && len(cond.Roles) == 0 {
		return false, nil
	}
	// should specify both roles and users, this condition is also verified on the role level
	if len(cond.Users) == 0 || len(cond.Roles) == 0 {
		return false, trace.BadParameter("the system does not support empty roles and users")
	}

	anyUser, err := parse.NewAnyMatcher(cond.Users)
	if err != nil {
		return false, trace.Wrap(err)
	}

	if anyUser.Match(impersonateUser.GetName()) {
		return true, nil
	}

	anyRole, err := parse.NewAnyMatcher(cond.Roles)
	if err != nil {
		return false, trace.Wrap(err)
	}

	for _, impersonateRole := range impersonateRoles {
		if anyRole.Match(impersonateRole.GetName()) {
			return true, nil
		}
	}

	return false, nil
}

// RoleMatcher defines an interface for a generic role matcher.
type RoleMatcher interface {
	Match(types.Role, types.RoleConditionType) (bool, error)
}

// RoleMatchers defines a list of matchers.
type RoleMatchers []RoleMatcher

// MatchAll returns true if all matchers in the set match.
func (m RoleMatchers) MatchAll(role types.Role, condition types.RoleConditionType) (bool, error) {
	for _, matcher := range m {
		match, err := matcher.Match(role, condition)
		if err != nil {
			return false, trace.Wrap(err)
		}
		if !match {
			return false, nil
		}
	}
	return true, nil
}

// MatchAny returns true if at least one of the matchers in the set matches.
//
// If the result is true, returns matcher that matched.
func (m RoleMatchers) MatchAny(role types.Role, condition types.RoleConditionType) (bool, RoleMatcher, error) {
	for _, matcher := range m {
		match, err := matcher.Match(role, condition)
		if err != nil {
			return false, nil, trace.Wrap(err)
		}
		if match {
			return true, matcher, nil
		}
	}
	return false, nil, nil
}

// DatabaseLabelsMatcher matches a role against a list of database server labels.
type DatabaseLabelsMatcher struct {
	Labels map[string]string
}

// Match matches database server labels against provided role and condition.
func (m *DatabaseLabelsMatcher) Match(role types.Role, condition types.RoleConditionType) (bool, error) {
	match, _, err := MatchLabels(role.GetDatabaseLabels(condition), m.Labels)
	return match, trace.Wrap(err)
}

// String returns the matcher's string representation.
func (m *DatabaseLabelsMatcher) String() string {
	return fmt.Sprintf("DatabaseLabelsMatcher(Labels=%v)", m.Labels)
}

// DatabaseUserMatcher matches a role against database account name.
type DatabaseUserMatcher struct {
	User string
}

// Match matches database account name against provided role and condition.
func (m *DatabaseUserMatcher) Match(role types.Role, condition types.RoleConditionType) (bool, error) {
	match, _ := MatchDatabaseUser(role.GetDatabaseUsers(condition), m.User)
	return match, nil
}

// String returns the matcher's string representation.
func (m *DatabaseUserMatcher) String() string {
	return fmt.Sprintf("DatabaseUserMatcher(User=%v)", m.User)
}

// DatabaseNameMatcher matches a role against database name.
type DatabaseNameMatcher struct {
	Name string
}

// Match matches database name against provided role and condition.
func (m *DatabaseNameMatcher) Match(role types.Role, condition types.RoleConditionType) (bool, error) {
	match, _ := MatchDatabaseName(role.GetDatabaseNames(condition), m.Name)
	return match, nil
}

// String returns the matcher's string representation.
func (m *DatabaseNameMatcher) String() string {
	return fmt.Sprintf("DatabaseNameMatcher(Name=%v)", m.Name)
}

// CheckAccessToDatabase checks if this role set has access to a particular database.
//
// The checker always checks the server namespace, other matchers are supplied
// by the caller.
func (set RoleSet) CheckAccessToDatabase(server types.DatabaseServer, mfa AccessMFAParams, matchers ...RoleMatcher) error {
	log := log.WithField(trace.Component, teleport.ComponentRBAC)
	if mfa.AlwaysRequired && !mfa.Verified {
		log.Debugf("Access to database %q denied, cluster requires per-session MFA", server.GetName())
		return ErrSessionMFARequired
	}
	// Check deny rules.
	for _, role := range set {
		matchNamespace, _ := MatchNamespace(role.GetNamespaces(Deny), server.GetNamespace())
		// Deny rules are greedy on purpose. They will always match if
		// at least one of the matchers returns true.
		if matchNamespace {
			match, matcher, err := RoleMatchers(matchers).MatchAny(role, Deny)
			if err != nil {
				return trace.Wrap(err)
			}
			if match {
				log.Debugf("Access to database %q denied, deny rule in role %q matched; %s.",
					server.GetName(), role.GetName(), matcher)
				return trace.AccessDenied("access to database denied")
			}
		}
	}
	allowed := false
	// Check allow rules.
	for _, role := range set {
		matchNamespace, _ := MatchNamespace(role.GetNamespaces(Allow), server.GetNamespace())
		// Allow rules are not greedy. They will match only if all of the
		// matchers return true.
		if matchNamespace {
			match, err := RoleMatchers(matchers).MatchAll(role, Allow)
			if err != nil {
				return trace.Wrap(err)
			}
			if match {
				if mfa.Verified {
					return nil
				}
				if role.GetOptions().RequireSessionMFA {
					log.Debugf("Access to database %q denied, role %q requires per-session MFA", server.GetName(), role.GetName())
					return ErrSessionMFARequired
				}
				// Check all remaining roles, even if we found a match.
				// RequireSessionMFA should be enforced when at least one role has
				// it.
				allowed = true
				log.Debugf("Access to database %q granted, allow rule in role %q matched.",
					server.GetName(), role.GetName())
				continue
			}
		}
	}
	if allowed {
		return nil
	}

	log.Debugf("Access to database %q denied, no allow rule matched.",
		server.GetName())
	return trace.AccessDenied("access to database denied")
}

// CanForwardAgents returns true if role set allows forwarding agents.
func (set RoleSet) CanForwardAgents() bool {
	for _, role := range set {
		if role.GetOptions().ForwardAgent.Value() {
			return true
		}
	}
	return false
}

// CanPortForward returns true if a role in the RoleSet allows port forwarding.
func (set RoleSet) CanPortForward() bool {
	for _, role := range set {
		if types.BoolDefaultTrue(role.GetOptions().PortForwarding) {
			return true
		}
	}
	return false
}

// MaybeCanReviewRequests attempts to guess if this RoleSet belongs
// to a user who should be submitting access reviews.  Because not all rolesets
// are derived from statically assigned roles, this may return false positives.
func (set RoleSet) MaybeCanReviewRequests() bool {
	for _, role := range set {
		if !role.GetAccessReviewConditions(Allow).IsZero() {
			// at least one nonzero allow directive exists for
			// review submission.
			return true
		}
	}
	return false
}

// PermitX11Forwarding returns true if this RoleSet allows X11 Forwarding.
func (set RoleSet) PermitX11Forwarding() bool {
	for _, role := range set {
		if role.GetOptions().PermitX11Forwarding.Value() {
			return true
		}
	}
	return false
}

// CertificateFormat returns the most permissive certificate format in a
// RoleSet.
func (set RoleSet) CertificateFormat() string {
	var formats []string

	for _, role := range set {
		// get the certificate format for each individual role. if a role does not
		// have a certificate format (like implicit roles) skip over it
		certificateFormat := role.GetOptions().CertificateFormat
		if certificateFormat == "" {
			continue
		}

		formats = append(formats, certificateFormat)
	}

	// if no formats were found, return standard
	if len(formats) == 0 {
		return constants.CertificateFormatStandard
	}

	// sort the slice so the most permissive is the first element
	sort.Slice(formats, func(i, j int) bool {
		return certificatePriority(formats[i]) < certificatePriority(formats[j])
	})

	return formats[0]
}

// EnhancedRecordingSet returns the set of enhanced session recording
// events to capture for thi role set.
func (set RoleSet) EnhancedRecordingSet() map[string]bool {
	m := make(map[string]bool)

	// Loop over all roles and create a set of all options.
	for _, role := range set {
		for _, opt := range role.GetOptions().BPF {
			m[opt] = true
		}
	}

	return m
}

// certificatePriority returns the priority of the certificate format. The
// most permissive has lowest value.
func certificatePriority(s string) int {
	switch s {
	case teleport.CertificateFormatOldSSH:
		return 0
	case constants.CertificateFormatStandard:
		return 1
	default:
		return 2
	}
}

// CheckAgentForward checks if the role can request to forward the SSH agent
// for this user.
func (set RoleSet) CheckAgentForward(login string) error {
	// check if we have permission to login and forward agent. we don't check
	// for deny rules because if you can't forward an agent if you can't login
	// in the first place.
	for _, role := range set {
		for _, l := range role.GetLogins(Allow) {
			if role.GetOptions().ForwardAgent.Value() && l == login {
				return nil
			}
		}
	}
	return trace.AccessDenied("%v can not forward agent for %v", set, login)
}

func (set RoleSet) String() string {
	if len(set) == 0 {
		return "user without assigned roles"
	}
	roleNames := make([]string, len(set))
	for i, role := range set {
		roleNames[i] = role.GetName()
	}
	return fmt.Sprintf("roles %v", strings.Join(roleNames, ","))
}

// CheckAccessToRule checks if the RoleSet provides access in the given
// namespace to the specified resource and verb.
// silent controls whether the access violations are logged.
func (set RoleSet) CheckAccessToRule(ctx RuleContext, namespace string, resource string, verb string, silent bool) error {
	whereParser, err := NewWhereParser(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	actionsParser, err := NewActionsParser(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	// check deny: a single match on a deny rule prohibits access
	for _, role := range set {
		matchNamespace, _ := MatchNamespace(role.GetNamespaces(Deny), types.ProcessNamespace(namespace))
		if matchNamespace {
			matched, err := MakeRuleSet(role.GetRules(Deny)).Match(whereParser, actionsParser, resource, verb)
			if err != nil {
				return trace.Wrap(err)
			}
			if matched {
				if !silent {
					log.WithFields(log.Fields{
						trace.Component: teleport.ComponentRBAC,
					}).Infof("Access to %v %v in namespace %v denied to %v: deny rule matched.",
						verb, resource, namespace, role.GetName())
				}
				return trace.AccessDenied("access denied to perform action '%s' on %s", verb, resource)
			}
		}
	}

	// check allow: if rule matches, grant access to resource
	for _, role := range set {
		matchNamespace, _ := MatchNamespace(role.GetNamespaces(Allow), types.ProcessNamespace(namespace))
		if matchNamespace {
			match, err := MakeRuleSet(role.GetRules(Allow)).Match(whereParser, actionsParser, resource, verb)
			if err != nil {
				return trace.Wrap(err)
			}
			if match {
				return nil
			}
		}
	}

	if !silent {
		log.WithFields(log.Fields{
			trace.Component: teleport.ComponentRBAC,
		}).Infof("Access to %v %v in namespace %v denied to %v: no allow rule matched.",
			verb, resource, namespace, set)
	}
	return trace.AccessDenied("access denied to perform action %q on %q", verb, resource)
}

// AccessMFAParams contains MFA-related parameters for CheckAccessTo* methods.
type AccessMFAParams struct {
	// AlwaysRequired is set when MFA is required for all sessions, regardless
	// of per-role options.
	AlwaysRequired bool
	// Verified is set when MFA has been verified by the caller.
	Verified bool
}

// SortedRoles sorts roles by name
type SortedRoles []types.Role

// Len returns length of a role list
func (s SortedRoles) Len() int {
	return len(s)
}

// Less compares roles by name
func (s SortedRoles) Less(i, j int) bool {
	return s[i].GetName() < s[j].GetName()
}

// Swap swaps two roles in a list
func (s SortedRoles) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// UnmarshalRole unmarshals the Role resource from JSON.
func UnmarshalRole(bytes []byte, opts ...MarshalOption) (types.Role, error) {
	var h types.ResourceHeader
	err := json.Unmarshal(bytes, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch h.Version {
	case types.V4:
		// V4 roles are identical to V3 except for their defaults
		fallthrough
	case types.V3:
		var role types.RoleV4
		if err := utils.FastUnmarshal(bytes, &role); err != nil {
			return nil, trace.BadParameter(err.Error())
		}

		if err := ValidateRole(&role); err != nil {
			return nil, trace.Wrap(err)
		}

		if cfg.ID != 0 {
			role.SetResourceID(cfg.ID)
		}
		if !cfg.Expires.IsZero() {
			role.SetExpiry(cfg.Expires)
		}
		return &role, nil
	}

	return nil, trace.BadParameter("role version %q is not supported", h.Version)
}

// MarshalRole marshals the Role resource to JSON.
func MarshalRole(role types.Role, opts ...MarshalOption) ([]byte, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch role := role.(type) {
	case *types.RoleV4:
		// V4 role version is compatible with V3
		if version := role.GetVersion(); version != types.V3 && version != types.V4 {
			return nil, trace.BadParameter("mismatched role version %v and type %T", version, role)
		}
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *role
			copy.SetResourceID(0)
			role = &copy
		}
		return utils.FastMarshal(role)
	default:
		return nil, trace.BadParameter("unrecognized role version %T", role)
	}
}

// DowngradeToV3 converts a V4 role to V3 so that it will be compatible with
// older instances. Makes a shallow copy if the conversion is necessary. The
// passed in role will not be mutated.
// DELETE IN 8.0.0
func DowngradeRoleToV3(r *types.RoleV4) (*types.RoleV4, error) {
	switch r.Version {
	case types.V3:
		return r, nil
	case types.V4:
		var downgraded types.RoleV4
		downgraded = *r
		downgraded.Version = types.V3

		// V3 roles will set the default labels to wildcard allow if they are
		// empty. To prevent this for roles which are created as V4 and
		// downgraded, set a placeholder label
		const labelKey = "__teleport_no_labels"
		labelVal := uuid.New()
		if len(r.Spec.Allow.NodeLabels) == 0 {
			downgraded.Spec.Allow.NodeLabels = types.Labels{labelKey: []string{labelVal}}
		}
		if len(r.Spec.Allow.AppLabels) == 0 {
			downgraded.Spec.Allow.AppLabels = types.Labels{labelKey: []string{labelVal}}
		}
		if len(r.Spec.Allow.KubernetesLabels) == 0 {
			downgraded.Spec.Allow.KubernetesLabels = types.Labels{labelKey: []string{labelVal}}
		}
		if len(r.Spec.Allow.DatabaseLabels) == 0 {
			downgraded.Spec.Allow.DatabaseLabels = types.Labels{labelKey: []string{labelVal}}
		}
		return &downgraded, nil
	default:
		return nil, trace.BadParameter("unrecognized role version %T", r.Version)
	}
}
