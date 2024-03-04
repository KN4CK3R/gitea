// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"time"

	asymkey_model "code.gitea.io/gitea/models/asymkey"
	audit_model "code.gitea.io/gitea/models/audit"
	auth_model "code.gitea.io/gitea/models/auth"
	git_model "code.gitea.io/gitea/models/git"
	organization_model "code.gitea.io/gitea/models/organization"
	perm_model "code.gitea.io/gitea/models/perm"
	repository_model "code.gitea.io/gitea/models/repo"
	secret_model "code.gitea.io/gitea/models/secret"
	user_model "code.gitea.io/gitea/models/user"
	webhook_model "code.gitea.io/gitea/models/webhook"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
)

type MessageContext struct {
	Action audit_model.Action
	Values []any
}

type Event struct {
	Action         audit_model.Action `json:"action"`
	Actor          TypeDescriptor     `json:"actor"`
	Scope          TypeDescriptor     `json:"scope"`
	Target         TypeDescriptor     `json:"target"`
	MessageContext MessageContext     `json:"message"`
	Time           time.Time          `json:"time"`
	IPAddress      string             `json:"ip_address"`
}

func buildEvent(ctx context.Context, action audit_model.Action, actor *user_model.User, scope, target any, values []any) *Event {
	return &Event{
		Action:         action,
		Actor:          typeToDescription(actor),
		Scope:          scopeToDescription(scope),
		Target:         typeToDescription(target),
		MessageContext: MessageContext{action, values},
		Time:           time.Now(),
		IPAddress:      tryGetIPAddress(ctx),
	}
}

func record(ctx context.Context, action audit_model.Action, actor *user_model.User, scope, target any, values []any) {
	if !setting.Audit.Enabled {
		return
	}

	e := buildEvent(ctx, action, actor, scope, target, values)

	if err := writeToFile(e); err != nil {
		log.Error("Error writing audit event to file: %v", err)
	}
	if err := writeToDatabase(ctx, e); err != nil {
		log.Error("Error writing audit event %+v to database: %v", e, err)
	}
}

func RecordUserImpersonation(ctx context.Context, impersonator, target *user_model.User) {
	record(ctx, audit_model.UserImpersonation, impersonator, impersonator, target, []any{impersonator.Name, target.Name})
}

func RecordUserCreate(ctx context.Context, doer, user *user_model.User) {
	action := audit_model.UserCreate
	if user.IsOrganization() {
		action = audit_model.OrganizationCreate
	}
	record(ctx, action, doer, user, user, []any{user.Name})
}

func RecordUserDelete(ctx context.Context, doer, user *user_model.User) {
	action := audit_model.UserDelete
	if user.IsOrganization() {
		action = audit_model.OrganizationDelete
	}
	record(ctx, action, doer, user, user, []any{user.Name})
}

func RecordUserAuthenticationFailTwoFactor(ctx context.Context, user *user_model.User) {
	record(ctx, audit_model.UserAuthenticationFailTwoFactor, user, user, user, []any{user.Name})
}

func RecordUserAuthenticationSource(ctx context.Context, doer, user *user_model.User) {
	record(ctx, audit_model.UserAuthenticationSource, doer, user, user, []any{user.Name})
}

func RecordUserActive(ctx context.Context, doer, user *user_model.User) {
	status := "active"
	if !user.IsActive {
		status = "inactive"
	}

	record(ctx, audit_model.UserActive, doer, user, user, []any{user.Name, status})
}

func RecordUserRestricted(ctx context.Context, doer, user *user_model.User) {
	status := "restricted"
	if !user.IsRestricted {
		status = "unrestricted"
	}

	record(ctx, audit_model.UserRestricted, doer, user, user, []any{user.Name, status})
}

func RecordUserAdmin(ctx context.Context, doer, user *user_model.User) {
	status := "admin"
	if !user.IsAdmin {
		status = "normal user"
	}

	record(ctx, audit_model.UserAdmin, doer, user, user, []any{user.Name, status})
}

func RecordUserName(ctx context.Context, doer, user *user_model.User) {
	action := audit_model.UserName
	if user.IsOrganization() {
		action = audit_model.OrganizationName
	}
	record(ctx, action, doer, user, user, []any{user.Name})
}

func RecordUserPassword(ctx context.Context, doer, user *user_model.User) {
	record(ctx, audit_model.UserPassword, doer, user, user, []any{user.Name})
}

func RecordUserPasswordResetRequest(ctx context.Context, doer, user *user_model.User) {
	record(ctx, audit_model.UserPasswordResetRequest, doer, user, user, []any{user.Name})
}

func RecordUserVisibility(ctx context.Context, doer, user *user_model.User) {
	action := audit_model.UserVisibility
	if user.IsOrganization() {
		action = audit_model.OrganizationVisibility
	}
	record(ctx, action, doer, user, user, []any{user.Name, user.Visibility.String()})
}

func RecordUserEmailPrimaryChange(ctx context.Context, doer, user *user_model.User, email *user_model.EmailAddress) {
	record(ctx, audit_model.UserEmailPrimaryChange, doer, user, email, []any{user.Name, email.Email})
}

func RecordUserEmailAdd(ctx context.Context, doer, user *user_model.User, email *user_model.EmailAddress) {
	record(ctx, audit_model.UserEmailAdd, doer, user, email, []any{email.Email, user.Name})
}

func RecordUserEmailActivate(ctx context.Context, doer, user *user_model.User, email *user_model.EmailAddress) {
	status := "active"
	if !email.IsActivated {
		status = "inactive"
	}

	record(ctx, audit_model.UserEmailActivate, doer, user, email, []any{email.Email, user.Name, status})
}

func RecordUserEmailRemove(ctx context.Context, doer, user *user_model.User, email *user_model.EmailAddress) {
	record(ctx, audit_model.UserEmailRemove, doer, user, email, []any{email.Email, user.Name})
}

func RecordUserTwoFactorEnable(ctx context.Context, doer, user *user_model.User) {
	record(ctx, audit_model.UserTwoFactorEnable, doer, user, user, []any{user.Name})
}

func RecordUserTwoFactorRegenerate(ctx context.Context, doer, user *user_model.User, tf *auth_model.TwoFactor) {
	record(ctx, audit_model.UserTwoFactorRegenerate, doer, user, tf, []any{user.Name})
}

func RecordUserTwoFactorDisable(ctx context.Context, doer, user *user_model.User, tf *auth_model.TwoFactor) {
	record(ctx, audit_model.UserTwoFactorDisable, doer, user, tf, []any{user.Name})
}

func RecordUserWebAuthAdd(ctx context.Context, doer, user *user_model.User, authn *auth_model.WebAuthnCredential) {
	record(ctx, audit_model.UserWebAuthAdd, doer, user, authn, []any{authn.Name, user.Name})
}

func RecordUserWebAuthRemove(ctx context.Context, doer, user *user_model.User, authn *auth_model.WebAuthnCredential) {
	record(ctx, audit_model.UserWebAuthRemove, doer, user, authn, []any{authn.Name, user.Name})
}

func RecordUserExternalLoginAdd(ctx context.Context, doer, user *user_model.User, externalLogin *user_model.ExternalLoginUser) {
	record(ctx, audit_model.UserExternalLoginAdd, doer, user, externalLogin.ExternalID, []any{user.Name, externalLogin.Provider})
}

func RecordUserExternalLoginRemove(ctx context.Context, doer, user *user_model.User, externalLogin *user_model.ExternalLoginUser) {
	record(ctx, audit_model.UserExternalLoginRemove, doer, user, externalLogin.ExternalID, []any{user.Name, externalLogin.Provider})
}

func RecordUserOpenIDAdd(ctx context.Context, doer, user *user_model.User, oid *user_model.UserOpenID) {
	record(ctx, audit_model.UserOpenIDAdd, doer, user, oid, []any{oid.URI, user.Name})
}

func RecordUserOpenIDRemove(ctx context.Context, doer, user *user_model.User, oid *user_model.UserOpenID) {
	record(ctx, audit_model.UserOpenIDRemove, doer, user, oid, []any{oid.URI, user.Name})
}

func RecordUserAccessTokenAdd(ctx context.Context, doer, user *user_model.User, token *auth_model.AccessToken) {
	record(ctx, audit_model.UserAccessTokenAdd, doer, user, token, []any{token.Name, user.Name, token.Scope})
}

func RecordUserAccessTokenRemove(ctx context.Context, doer, user *user_model.User, token *auth_model.AccessToken) {
	record(ctx, audit_model.UserAccessTokenRemove, doer, user, token, []any{token.Name, user.Name})
}

func RecordOAuth2ApplicationAdd(ctx context.Context, doer, user *user_model.User, app *auth_model.OAuth2Application) {
	if user == nil {
		record(ctx, audit_model.SystemOAuth2ApplicationAdd, doer, &systemObject, app, []any{app.Name})
	} else if user.IsOrganization() {
		record(ctx, audit_model.OrganizationOAuth2ApplicationAdd, doer, user, app, []any{app.Name, user.Name})
	} else {
		record(ctx, audit_model.UserOAuth2ApplicationAdd, doer, user, app, []any{app.Name, user.Name})
	}
}

func RecordOAuth2ApplicationUpdate(ctx context.Context, doer, user *user_model.User, app *auth_model.OAuth2Application) {
	if user == nil {
		record(ctx, audit_model.SystemOAuth2ApplicationUpdate, doer, &systemObject, app, []any{app.Name})
	} else if user.IsOrganization() {
		record(ctx, audit_model.OrganizationOAuth2ApplicationUpdate, doer, user, app, []any{app.Name, user.Name})
	} else {
		record(ctx, audit_model.UserOAuth2ApplicationUpdate, doer, user, app, []any{app.Name, user.Name})
	}
}

func RecordOAuth2ApplicationSecret(ctx context.Context, doer, user *user_model.User, app *auth_model.OAuth2Application) {
	if user == nil {
		record(ctx, audit_model.SystemOAuth2ApplicationSecret, doer, &systemObject, app, []any{app.Name})
	} else if user.IsOrganization() {
		record(ctx, audit_model.OrganizationOAuth2ApplicationSecret, doer, user, app, []any{app.Name, user.Name})
	} else {
		record(ctx, audit_model.UserOAuth2ApplicationSecret, doer, user, app, []any{app.Name, user.Name})
	}
}

func RecordUserOAuth2ApplicationGrant(ctx context.Context, doer, owner *user_model.User, app *auth_model.OAuth2Application, grant *auth_model.OAuth2Grant) {
	record(ctx, audit_model.UserOAuth2ApplicationGrant, doer, owner, grant, []any{app.Name, owner.Name})
}

func RecordUserOAuth2ApplicationRevoke(ctx context.Context, doer, owner *user_model.User, app *auth_model.OAuth2Application, grant *auth_model.OAuth2Grant) {
	record(ctx, audit_model.UserOAuth2ApplicationRevoke, doer, owner, grant, []any{app.Name, owner.Name})
}

func RecordOAuth2ApplicationRemove(ctx context.Context, doer, user *user_model.User, app *auth_model.OAuth2Application) {
	if user == nil {
		record(ctx, audit_model.SystemOAuth2ApplicationRemove, doer, &systemObject, app, []any{app.Name})
	} else if user.IsOrganization() {
		record(ctx, audit_model.OrganizationOAuth2ApplicationRemove, doer, user, app, []any{app.Name, user.Name})
	} else {
		record(ctx, audit_model.UserOAuth2ApplicationRemove, doer, user, app, []any{app.Name, user.Name})
	}
}

func RecordUserKeySSHAdd(ctx context.Context, doer, user *user_model.User, key *asymkey_model.PublicKey) {
	record(ctx, audit_model.UserKeySSHAdd, doer, user, key, []any{key.Fingerprint, user.Name})
}

func RecordUserKeySSHRemove(ctx context.Context, doer, user *user_model.User, key *asymkey_model.PublicKey) {
	record(ctx, audit_model.UserKeySSHRemove, doer, user, key, []any{key.Fingerprint, user.Name})
}

func RecordUserKeyPrincipalAdd(ctx context.Context, doer, user *user_model.User, key *asymkey_model.PublicKey) {
	record(ctx, audit_model.UserKeyPrincipalAdd, doer, user, key, []any{key.Name, user.Name})
}

func RecordUserKeyPrincipalRemove(ctx context.Context, doer, user *user_model.User, key *asymkey_model.PublicKey) {
	record(ctx, audit_model.UserKeyPrincipalRemove, doer, user, key, []any{key.Name, user.Name})
}

func RecordUserKeyGPGAdd(ctx context.Context, doer, user *user_model.User, key *asymkey_model.GPGKey) {
	record(ctx, audit_model.UserKeyGPGAdd, doer, user, key, []any{key.KeyID, user.Name})
}

func RecordUserKeyGPGRemove(ctx context.Context, doer, user *user_model.User, key *asymkey_model.GPGKey) {
	record(ctx, audit_model.UserKeyGPGRemove, doer, user, key, []any{key.KeyID, user.Name})
}

func RecordSecretAdd(ctx context.Context, doer, owner *user_model.User, repo *repository_model.Repository, secret *secret_model.Secret) {
	if owner == nil {
		record(ctx, audit_model.RepositorySecretAdd, doer, repo, secret, []any{secret.Name, repo.FullName()})
	} else if owner.IsOrganization() {
		record(ctx, audit_model.OrganizationSecretAdd, doer, owner, secret, []any{secret.Name, owner.Name})
	} else {
		record(ctx, audit_model.UserSecretAdd, doer, owner, secret, []any{secret.Name, owner.Name})
	}
}

func RecordSecretUpdate(ctx context.Context, doer, owner *user_model.User, repo *repository_model.Repository, secret *secret_model.Secret) {
	if owner == nil {
		record(ctx, audit_model.RepositorySecretUpdate, doer, repo, secret, []any{secret.Name, repo.FullName()})
	} else if owner.IsOrganization() {
		record(ctx, audit_model.OrganizationSecretUpdate, doer, owner, secret, []any{secret.Name, owner.Name})
	} else {
		record(ctx, audit_model.UserSecretUpdate, doer, owner, secret, []any{secret.Name, owner.Name})
	}
}

func RecordSecretRemove(ctx context.Context, doer, owner *user_model.User, repo *repository_model.Repository, secret *secret_model.Secret) {
	if owner == nil {
		record(ctx, audit_model.RepositorySecretRemove, doer, repo, secret, []any{secret.Name, repo.FullName()})
	} else if owner.IsOrganization() {
		record(ctx, audit_model.OrganizationSecretRemove, doer, owner, secret, []any{secret.Name, owner.Name})
	} else {
		record(ctx, audit_model.UserSecretRemove, doer, owner, secret, []any{secret.Name, owner.Name})
	}
}

func RecordWebhookAdd(ctx context.Context, doer, owner *user_model.User, repo *repository_model.Repository, hook *webhook_model.Webhook) {
	if owner == nil && repo == nil {
		record(ctx, audit_model.SystemWebhookAdd, doer, &systemObject, hook, []any{hook.URL})
	} else if repo != nil {
		record(ctx, audit_model.RepositoryWebhookAdd, doer, repo, hook, []any{hook.URL, repo.FullName()})
	} else if owner.IsOrganization() {
		record(ctx, audit_model.OrganizationWebhookAdd, doer, owner, hook, []any{hook.URL, owner.Name})
	} else {
		record(ctx, audit_model.UserWebhookAdd, doer, owner, hook, []any{hook.URL, owner.Name})
	}
}

func RecordWebhookUpdate(ctx context.Context, doer, owner *user_model.User, repo *repository_model.Repository, hook *webhook_model.Webhook) {
	if owner == nil && repo == nil {
		record(ctx, audit_model.SystemWebhookUpdate, doer, &systemObject, hook, []any{hook.URL})
	} else if repo != nil {
		record(ctx, audit_model.RepositoryWebhookUpdate, doer, repo, hook, []any{hook.URL, repo.FullName()})
	} else if owner.IsOrganization() {
		record(ctx, audit_model.OrganizationWebhookUpdate, doer, owner, hook, []any{hook.URL, owner.Name})
	} else {
		record(ctx, audit_model.UserWebhookUpdate, doer, owner, hook, []any{hook.URL, owner.Name})
	}
}

func RecordWebhookRemove(ctx context.Context, doer, owner *user_model.User, repo *repository_model.Repository, hook *webhook_model.Webhook) {
	if owner == nil && repo == nil {
		record(ctx, audit_model.SystemWebhookRemove, doer, &systemObject, hook, []any{hook.URL})
	} else if repo != nil {
		record(ctx, audit_model.RepositoryWebhookRemove, doer, repo, hook, []any{hook.URL, repo.FullName()})
	} else if owner.IsOrganization() {
		record(ctx, audit_model.OrganizationWebhookRemove, doer, owner, hook, []any{hook.URL, owner.Name})
	} else {
		record(ctx, audit_model.UserWebhookRemove, doer, owner, hook, []any{hook.URL, owner.Name})
	}
}

func RecordOrganizationTeamAdd(ctx context.Context, doer *user_model.User, org *organization_model.Organization, team *organization_model.Team) {
	record(ctx, audit_model.OrganizationTeamAdd, doer, org, team, []any{team.Name, org.Name})
}

func RecordOrganizationTeamUpdate(ctx context.Context, doer *user_model.User, org *organization_model.Organization, team *organization_model.Team) {
	record(ctx, audit_model.OrganizationTeamUpdate, doer, org, team, []any{org.Name, team.Name})
}

func RecordOrganizationTeamRemove(ctx context.Context, doer *user_model.User, org *organization_model.Organization, team *organization_model.Team) {
	record(ctx, audit_model.OrganizationTeamRemove, doer, org, team, []any{team.Name, org.Name})
}

func RecordOrganizationTeamPermission(ctx context.Context, doer *user_model.User, org *organization_model.Organization, team *organization_model.Team) {
	record(ctx, audit_model.OrganizationTeamPermission, doer, org, team, []any{org.Name, team.Name, team.AccessMode.String()})
}

func RecordOrganizationTeamMemberAdd(ctx context.Context, doer *user_model.User, org *organization_model.Organization, team *organization_model.Team, member *user_model.User) {
	record(ctx, audit_model.OrganizationTeamMemberAdd, doer, org, team, []any{member.Name, org.Name, team.Name})
}

func RecordOrganizationTeamMemberRemove(ctx context.Context, doer *user_model.User, org *organization_model.Organization, team *organization_model.Team, member *user_model.User) {
	record(ctx, audit_model.OrganizationTeamMemberRemove, doer, org, team, []any{member.Name, org.Name, team.Name})
}

func RecordRepositoryCreate(ctx context.Context, doer *user_model.User, repo *repository_model.Repository) {
	record(ctx, audit_model.RepositoryCreate, doer, repo, repo, []any{repo.FullName()})
}

func RecordRepositoryCreateFork(ctx context.Context, doer *user_model.User, repo, baseRepo *repository_model.Repository) {
	record(ctx, audit_model.RepositoryCreateFork, doer, repo, repo, []any{repo.FullName(), baseRepo.FullName()})
}

func RecordRepositoryArchive(ctx context.Context, doer *user_model.User, repo *repository_model.Repository) {
	record(ctx, audit_model.RepositoryArchive, doer, repo, repo, []any{repo.FullName()})
}

func RecordRepositoryUnarchive(ctx context.Context, doer *user_model.User, repo *repository_model.Repository) {
	record(ctx, audit_model.RepositoryUnarchive, doer, repo, repo, []any{repo.FullName()})
}

func RecordRepositoryDelete(ctx context.Context, doer *user_model.User, repo *repository_model.Repository) {
	record(ctx, audit_model.RepositoryDelete, doer, repo, repo, []any{repo.FullName()})
}

func RecordRepositoryName(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, previousName string) {
	record(ctx, audit_model.RepositoryName, doer, repo, repo, []any{previousName, repo.FullName()})
}

func RecordRepositoryVisibility(ctx context.Context, doer *user_model.User, repo *repository_model.Repository) {
	status := "public"
	if repo.IsPrivate {
		status = "private"
	}

	record(ctx, audit_model.RepositoryVisibility, doer, repo, repo, []any{repo.FullName(), status})
}

func RecordRepositoryConvertFork(ctx context.Context, doer *user_model.User, repo *repository_model.Repository) {
	record(ctx, audit_model.RepositoryConvertFork, doer, repo, repo, []any{repo.FullName()})
}

func RecordRepositoryConvertMirror(ctx context.Context, doer *user_model.User, repo *repository_model.Repository) {
	record(ctx, audit_model.RepositoryConvertMirror, doer, repo, repo, []any{repo.FullName()})
}

func RecordRepositoryMirrorPushAdd(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, mirror *repository_model.PushMirror) {
	record(ctx, audit_model.RepositoryMirrorPushAdd, doer, repo, mirror, []any{mirror.RemoteAddress, repo.FullName()})
}

func RecordRepositoryMirrorPushRemove(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, mirror *repository_model.PushMirror) {
	record(ctx, audit_model.RepositoryMirrorPushRemove, doer, repo, mirror, []any{mirror.RemoteAddress, repo.FullName()})
}

func RecordRepositorySigningVerification(ctx context.Context, doer *user_model.User, repo *repository_model.Repository) {
	record(ctx, audit_model.RepositorySigningVerification, doer, repo, repo, []any{repo.FullName(), repo.TrustModel.String()})
}

func RecordRepositoryTransferStart(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, newOwner *user_model.User) {
	record(ctx, audit_model.RepositoryTransferStart, doer, repo, repo, []any{repo.FullName(), newOwner.Name})
}

func RecordRepositoryTransferFinish(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, oldOwner *user_model.User) {
	record(ctx, audit_model.RepositoryTransferFinish, doer, repo, repo, []any{repo.FullName(), oldOwner.Name, repo.OwnerName})
}

func RecordRepositoryTransferCancel(ctx context.Context, doer *user_model.User, repo *repository_model.Repository) {
	record(ctx, audit_model.RepositoryTransferCancel, doer, repo, repo, []any{repo.FullName()})
}

func RecordRepositoryWikiDelete(ctx context.Context, doer *user_model.User, repo *repository_model.Repository) {
	record(ctx, audit_model.RepositoryWikiDelete, doer, repo, repo, []any{repo.FullName()})
}

func RecordRepositoryCollaboratorAdd(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, collaborator *user_model.User) {
	record(ctx, audit_model.RepositoryCollaboratorAdd, doer, repo, collaborator, []any{collaborator.Name, repo.FullName()})
}

func RecordRepositoryCollaboratorAccess(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, collaborator *user_model.User, accessMode perm_model.AccessMode) {
	record(ctx, audit_model.RepositoryCollaboratorAccess, doer, repo, collaborator, []any{collaborator.Name, repo.FullName(), accessMode.String()})
}

func RecordRepositoryCollaboratorRemove(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, collaborator *user_model.User) {
	record(ctx, audit_model.RepositoryCollaboratorRemove, doer, repo, collaborator, []any{collaborator.Name, repo.FullName()})
}

func RecordRepositoryCollaboratorTeamAdd(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, team *organization_model.Team) {
	record(ctx, audit_model.RepositoryCollaboratorTeamAdd, doer, repo, team, []any{team.Name, repo.FullName()})
}

func RecordRepositoryCollaboratorTeamRemove(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, team *organization_model.Team) {
	record(ctx, audit_model.RepositoryCollaboratorTeamRemove, doer, repo, team, []any{team.Name, repo.FullName()})
}

func RecordRepositoryBranchDefault(ctx context.Context, doer *user_model.User, repo *repository_model.Repository) {
	record(ctx, audit_model.RepositoryBranchDefault, doer, repo, repo, []any{repo.FullName(), repo.DefaultBranch})
}

func RecordRepositoryBranchProtectionAdd(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, protectBranch *git_model.ProtectedBranch) {
	record(ctx, audit_model.RepositoryBranchProtectionAdd, doer, repo, protectBranch, []any{protectBranch.RuleName, repo.FullName()})
}

func RecordRepositoryBranchProtectionUpdate(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, protectBranch *git_model.ProtectedBranch) {
	record(ctx, audit_model.RepositoryBranchProtectionUpdate, doer, repo, protectBranch, []any{protectBranch.RuleName, repo.FullName()})
}

func RecordRepositoryBranchProtectionRemove(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, protectBranch *git_model.ProtectedBranch) {
	record(ctx, audit_model.RepositoryBranchProtectionRemove, doer, repo, protectBranch, []any{protectBranch.RuleName, repo.FullName()})
}

func RecordRepositoryTagProtectionAdd(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, protectedTag *git_model.ProtectedTag) {
	record(ctx, audit_model.RepositoryTagProtectionAdd, doer, repo, protectedTag, []any{protectedTag.NamePattern, repo.FullName()})
}

func RecordRepositoryTagProtectionUpdate(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, protectedTag *git_model.ProtectedTag) {
	record(ctx, audit_model.RepositoryTagProtectionUpdate, doer, repo, protectedTag, []any{protectedTag.NamePattern, repo.FullName()})
}

func RecordRepositoryTagProtectionRemove(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, protectedTag *git_model.ProtectedTag) {
	record(ctx, audit_model.RepositoryTagProtectionRemove, doer, repo, protectedTag, []any{protectedTag.NamePattern, repo.FullName()})
}

func RecordRepositoryDeployKeyAdd(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, deployKey *asymkey_model.DeployKey) {
	record(ctx, audit_model.RepositoryDeployKeyAdd, doer, repo, deployKey, []any{deployKey.Name, repo.FullName()})
}

func RecordRepositoryDeployKeyRemove(ctx context.Context, doer *user_model.User, repo *repository_model.Repository, deployKey *asymkey_model.DeployKey) {
	record(ctx, audit_model.RepositoryDeployKeyRemove, doer, repo, deployKey, []any{deployKey.Name, repo.FullName()})
}

func RecordSystemStartup(ctx context.Context, doer *user_model.User, version string) {
	// Do not change this message anymore. We guarantee the stability of this message for users wanting to parse the log themselves to be able to trace back events across gitea versions.
	record(ctx, audit_model.SystemStartup, doer, &systemObject, &systemObject, []any{version})
}

func RecordSystemShutdown(ctx context.Context, doer *user_model.User) {
	record(ctx, audit_model.SystemShutdown, doer, &systemObject, &systemObject, []any{})
}

func RecordSystemAuthenticationSourceAdd(ctx context.Context, doer *user_model.User, authSource *auth_model.Source) {
	record(ctx, audit_model.SystemAuthenticationSourceAdd, doer, &systemObject, authSource, []any{authSource.Name, authSource.Type.String()})
}

func RecordSystemAuthenticationSourceUpdate(ctx context.Context, doer *user_model.User, authSource *auth_model.Source) {
	record(ctx, audit_model.SystemAuthenticationSourceUpdate, doer, &systemObject, authSource, []any{authSource.Name})
}

func RecordSystemAuthenticationSourceRemove(ctx context.Context, doer *user_model.User, authSource *auth_model.Source) {
	record(ctx, audit_model.SystemAuthenticationSourceRemove, doer, &systemObject, authSource, []any{authSource.Name})
}
