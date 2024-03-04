// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

type Action string

const (
	UserImpersonation               Action = "user:impersonation"
	UserCreate                      Action = "user:create"
	UserDelete                      Action = "user:delete"
	UserAuthenticationFailTwoFactor Action = "user:authentication:fail:twofactor"
	UserAuthenticationSource        Action = "user:authentication:source"
	UserActive                      Action = "user:active"
	UserRestricted                  Action = "user:restricted"
	UserAdmin                       Action = "user:admin"
	UserName                        Action = "user:name"
	UserPassword                    Action = "user:password"
	UserPasswordResetRequest        Action = "user:password:resetrequest"
	UserVisibility                  Action = "user:visibility"
	UserEmailPrimaryChange          Action = "user:email:primary"
	UserEmailAdd                    Action = "user:email:add"
	UserEmailActivate               Action = "user:email:activate"
	UserEmailRemove                 Action = "user:email:remove"
	UserTwoFactorEnable             Action = "user:twofactor:enable"
	UserTwoFactorRegenerate         Action = "user:twofactor:regenerate"
	UserTwoFactorDisable            Action = "user:twofactor:disable"
	UserWebAuthAdd                  Action = "user:webauth:add"
	UserWebAuthRemove               Action = "user:webauth:remove"
	UserExternalLoginAdd            Action = "user:externallogin:add"
	UserExternalLoginRemove         Action = "user:externallogin:remove"
	UserOpenIDAdd                   Action = "user:openid:add"
	UserOpenIDRemove                Action = "user:openid:remove"
	UserAccessTokenAdd              Action = "user:accesstoken:add"
	UserAccessTokenRemove           Action = "user:accesstoken:remove"
	UserOAuth2ApplicationAdd        Action = "user:oauth2application:add"
	UserOAuth2ApplicationUpdate     Action = "user:oauth2application:update"
	UserOAuth2ApplicationSecret     Action = "user:oauth2application:secret"
	UserOAuth2ApplicationGrant      Action = "user:oauth2application:grant"
	UserOAuth2ApplicationRevoke     Action = "user:oauth2application:revoke"
	UserOAuth2ApplicationRemove     Action = "user:oauth2application:remove"
	UserKeySSHAdd                   Action = "user:key:ssh:add"
	UserKeySSHRemove                Action = "user:key:ssh:remove"
	UserKeyPrincipalAdd             Action = "user:key:principal:add"
	UserKeyPrincipalRemove          Action = "user:key:principal:remove"
	UserKeyGPGAdd                   Action = "user:key:gpg:add"
	UserKeyGPGRemove                Action = "user:key:gpg:remove"
	UserSecretAdd                   Action = "user:secret:add"
	UserSecretUpdate                Action = "user:secret:update"
	UserSecretRemove                Action = "user:secret:remove"
	UserWebhookAdd                  Action = "user:webhook:add"
	UserWebhookUpdate               Action = "user:webhook:update"
	UserWebhookRemove               Action = "user:webhook:remove"

	OrganizationCreate                  Action = "organization:create"
	OrganizationDelete                  Action = "organization:delete"
	OrganizationName                    Action = "organization:name"
	OrganizationVisibility              Action = "organization:visibility"
	OrganizationTeamAdd                 Action = "organization:team:add"
	OrganizationTeamUpdate              Action = "organization:team:update"
	OrganizationTeamRemove              Action = "organization:team:remove"
	OrganizationTeamPermission          Action = "organization:team:permission"
	OrganizationTeamMemberAdd           Action = "organization:team:member:add"
	OrganizationTeamMemberRemove        Action = "organization:team:member:remove"
	OrganizationOAuth2ApplicationAdd    Action = "organization:oauth2application:add"
	OrganizationOAuth2ApplicationUpdate Action = "organization:oauth2application:update"
	OrganizationOAuth2ApplicationSecret Action = "organization:oauth2application:secret"
	OrganizationOAuth2ApplicationRemove Action = "organization:oauth2application:remove"
	OrganizationSecretAdd               Action = "organization:secret:add"
	OrganizationSecretUpdate            Action = "organization:secret:update"
	OrganizationSecretRemove            Action = "organization:secret:remove"
	OrganizationWebhookAdd              Action = "organization:webhook:add"
	OrganizationWebhookUpdate           Action = "organization:webhook:update"
	OrganizationWebhookRemove           Action = "organization:webhook:remove"

	RepositoryCreate                 Action = "repository:create"
	RepositoryCreateFork             Action = "repository:create:fork"
	RepositoryArchive                Action = "repository:archive"
	RepositoryUnarchive              Action = "repository:unarchive"
	RepositoryDelete                 Action = "repository:delete"
	RepositoryName                   Action = "repository:name"
	RepositoryVisibility             Action = "repository:visibility"
	RepositoryConvertFork            Action = "repository:convert:fork"
	RepositoryConvertMirror          Action = "repository:convert:mirror"
	RepositoryMirrorPushAdd          Action = "repository:mirror:push:add"
	RepositoryMirrorPushRemove       Action = "repository:mirror:push:remove"
	RepositorySigningVerification    Action = "repository:signingverification"
	RepositoryTransferStart          Action = "repository:transfer:start"
	RepositoryTransferFinish         Action = "repository:transfer:finish"
	RepositoryTransferCancel         Action = "repository:transfer:cancel"
	RepositoryWikiDelete             Action = "repository:wiki:delete"
	RepositoryCollaboratorAdd        Action = "repository:collaborator:add"
	RepositoryCollaboratorAccess     Action = "repository:collaborator:access"
	RepositoryCollaboratorRemove     Action = "repository:collaborator:remove"
	RepositoryCollaboratorTeamAdd    Action = "repository:collaborator:team:add"
	RepositoryCollaboratorTeamRemove Action = "repository:collaborator:team:remove"
	RepositoryBranchDefault          Action = "repository:branch:default"
	RepositoryBranchProtectionAdd    Action = "repository:branch:protection:add"
	RepositoryBranchProtectionUpdate Action = "repository:branch:protection:update"
	RepositoryBranchProtectionRemove Action = "repository:branch:protection:remove"
	RepositoryTagProtectionAdd       Action = "repository:tag:protection:add"
	RepositoryTagProtectionUpdate    Action = "repository:tag:protection:update"
	RepositoryTagProtectionRemove    Action = "repository:tag:protection:remove"
	RepositoryWebhookAdd             Action = "repository:webhook:add"
	RepositoryWebhookUpdate          Action = "repository:webhook:update"
	RepositoryWebhookRemove          Action = "repository:webhook:remove"
	RepositoryDeployKeyAdd           Action = "repository:deploykey:add"
	RepositoryDeployKeyRemove        Action = "repository:deploykey:remove"
	RepositorySecretAdd              Action = "repository:secret:add"
	RepositorySecretUpdate           Action = "repository:secret:update"
	RepositorySecretRemove           Action = "repository:secret:remove"

	SystemStartup                    Action = "system:startup"
	SystemShutdown                   Action = "system:shutdown"
	SystemWebhookAdd                 Action = "system:webhook:add"
	SystemWebhookUpdate              Action = "system:webhook:update"
	SystemWebhookRemove              Action = "system:webhook:remove"
	SystemAuthenticationSourceAdd    Action = "system:authenticationsource:add"
	SystemAuthenticationSourceUpdate Action = "system:authenticationsource:update"
	SystemAuthenticationSourceRemove Action = "system:authenticationsource:remove"
	SystemOAuth2ApplicationAdd       Action = "system:oauth2application:add"
	SystemOAuth2ApplicationUpdate    Action = "system:oauth2application:update"
	SystemOAuth2ApplicationSecret    Action = "system:oauth2application:secret"
	SystemOAuth2ApplicationRemove    Action = "system:oauth2application:remove"
)

func (a Action) LocaleKey() string {
	switch a {
	case UserImpersonation:
		return "audit.action.user.impersonation"
	case UserCreate:
		return "audit.action.user.create"
	case UserDelete:
		return "audit.action.user.delete"
	case UserAuthenticationFailTwoFactor:
		return "audit.action.user.authentication.fail.twofactor"
	case UserAuthenticationSource:
		return "audit.action.user.authentication.source"
	case UserActive:
		return "audit.action.user.active"
	case UserRestricted:
		return "audit.action.user.restricted"
	case UserAdmin:
		return "audit.action.user.admin"
	case UserName:
		return "audit.action.user.name"
	case UserPassword:
		return "audit.action.user.password"
	case UserPasswordResetRequest:
		return "audit.action.user.password.resetrequest"
	case UserVisibility:
		return "audit.action.user.visibility"
	case UserEmailPrimaryChange:
		return "audit.action.user.email.primary"
	case UserEmailAdd:
		return "audit.action.user.email.add"
	case UserEmailActivate:
		return "audit.action.user.email.activate"
	case UserEmailRemove:
		return "audit.action.user.email.remove"
	case UserTwoFactorEnable:
		return "audit.action.user.twofactor.enable"
	case UserTwoFactorRegenerate:
		return "audit.action.user.twofactor.regenerate"
	case UserTwoFactorDisable:
		return "audit.action.user.twofactor.disable"
	case UserWebAuthAdd:
		return "audit.action.user.webauth.add"
	case UserWebAuthRemove:
		return "audit.action.user.webauth.remove"
	case UserExternalLoginAdd:
		return "audit.action.user.externallogin.add"
	case UserExternalLoginRemove:
		return "audit.action.user.externallogin.remove"
	case UserOpenIDAdd:
		return "audit.action.user.openid.add"
	case UserOpenIDRemove:
		return "audit.action.user.openid.remove"
	case UserAccessTokenAdd:
		return "audit.action.user.accesstoken.add"
	case UserAccessTokenRemove:
		return "audit.action.user.accesstoken.remove"
	case UserOAuth2ApplicationAdd:
		return "audit.action.user.oauth2application.add"
	case UserOAuth2ApplicationUpdate:
		return "audit.action.user.oauth2application.update"
	case UserOAuth2ApplicationSecret:
		return "audit.action.user.oauth2application.secret"
	case UserOAuth2ApplicationGrant:
		return "audit.action.user.oauth2application.grant"
	case UserOAuth2ApplicationRevoke:
		return "audit.action.user.oauth2application.revoke"
	case UserOAuth2ApplicationRemove:
		return "audit.action.user.oauth2application.remove"
	case UserKeySSHAdd:
		return "audit.action.user.key.ssh.add"
	case UserKeySSHRemove:
		return "audit.action.user.key.ssh.remove"
	case UserKeyPrincipalAdd:
		return "audit.action.user.key.principal.add"
	case UserKeyPrincipalRemove:
		return "audit.action.user.key.principal.remove"
	case UserKeyGPGAdd:
		return "audit.action.user.key.gpg.add"
	case UserKeyGPGRemove:
		return "audit.action.user.key.gpg.remove"
	case UserSecretAdd:
		return "audit.action.user.secret.add"
	case UserSecretUpdate:
		return "audit.action.user.secret.update"
	case UserSecretRemove:
		return "audit.action.user.secret.remove"
	case UserWebhookAdd:
		return "audit.action.user.webhook.add"
	case UserWebhookUpdate:
		return "audit.action.user.webhook.update"
	case UserWebhookRemove:
		return "audit.action.user.webhook.remove"

	case OrganizationCreate:
		return "audit.action.organization.create"
	case OrganizationDelete:
		return "audit.action.organization.delete"
	case OrganizationName:
		return "audit.action.organization.name"
	case OrganizationVisibility:
		return "audit.action.organization.visibility"
	case OrganizationTeamAdd:
		return "audit.action.organization.team.add"
	case OrganizationTeamUpdate:
		return "audit.action.organization.team.update"
	case OrganizationTeamRemove:
		return "audit.action.organization.team.remove"
	case OrganizationTeamPermission:
		return "audit.action.organization.team.permission"
	case OrganizationTeamMemberAdd:
		return "audit.action.organization.team.member.add"
	case OrganizationTeamMemberRemove:
		return "audit.action.organization.team.member.remove"
	case OrganizationOAuth2ApplicationAdd:
		return "audit.action.organization.oauth2application.add"
	case OrganizationOAuth2ApplicationUpdate:
		return "audit.action.organization.oauth2application.update"
	case OrganizationOAuth2ApplicationSecret:
		return "audit.action.organization.oauth2application.secret"
	case OrganizationOAuth2ApplicationRemove:
		return "audit.action.organization.oauth2application.remove"
	case OrganizationSecretAdd:
		return "audit.action.organization.secret.add"
	case OrganizationSecretUpdate:
		return "audit.action.organization.secret.update"
	case OrganizationSecretRemove:
		return "audit.action.organization.secret.remove"
	case OrganizationWebhookAdd:
		return "audit.action.organization.webhook.add"
	case OrganizationWebhookUpdate:
		return "audit.action.organization.webhook.update"
	case OrganizationWebhookRemove:
		return "audit.action.organization.webhook.remove"

	case RepositoryCreate:
		return "audit.action.repository.create"
	case RepositoryCreateFork:
		return "audit.action.repository.create.fork"
	case RepositoryArchive:
		return "audit.action.repository.archive"
	case RepositoryUnarchive:
		return "audit.action.repository.unarchive"
	case RepositoryDelete:
		return "audit.action.repository.delete"
	case RepositoryName:
		return "audit.action.repository.name"
	case RepositoryVisibility:
		return "audit.action.repository.visibility"
	case RepositoryConvertFork:
		return "audit.action.repository.convert.fork"
	case RepositoryConvertMirror:
		return "audit.action.repository.convert.mirror"
	case RepositoryMirrorPushAdd:
		return "audit.action.repository.mirror.push.add"
	case RepositoryMirrorPushRemove:
		return "audit.action.repository.mirror.push.remove"
	case RepositorySigningVerification:
		return "audit.action.repository.signingverification"
	case RepositoryTransferStart:
		return "audit.action.repository.transfer.start"
	case RepositoryTransferFinish:
		return "audit.action.repository.transfer.finish"
	case RepositoryTransferCancel:
		return "audit.action.repository.transfer.cancel"
	case RepositoryWikiDelete:
		return "audit.action.repository.wiki.delete"
	case RepositoryCollaboratorAdd:
		return "audit.action.repository.collaborator.add"
	case RepositoryCollaboratorAccess:
		return "audit.action.repository.collaborator.access"
	case RepositoryCollaboratorRemove:
		return "audit.action.repository.collaborator.remove"
	case RepositoryCollaboratorTeamAdd:
		return "audit.action.repository.collaborator.team.add"
	case RepositoryCollaboratorTeamRemove:
		return "audit.action.repository.collaborator.team.remove"
	case RepositoryBranchDefault:
		return "audit.action.repository.branch.default"
	case RepositoryBranchProtectionAdd:
		return "audit.action.repository.branch.protection.add"
	case RepositoryBranchProtectionUpdate:
		return "audit.action.repository.branch.protection.update"
	case RepositoryBranchProtectionRemove:
		return "audit.action.repository.branch.protection.remove"
	case RepositoryTagProtectionAdd:
		return "audit.action.repository.tag.protection.add"
	case RepositoryTagProtectionUpdate:
		return "audit.action.repository.tag.protection.update"
	case RepositoryTagProtectionRemove:
		return "audit.action.repository.tag.protection.remove"
	case RepositoryWebhookAdd:
		return "audit.action.repository.webhook.add"
	case RepositoryWebhookUpdate:
		return "audit.action.repository.webhook.update"
	case RepositoryWebhookRemove:
		return "audit.action.repository.webhook.remove"
	case RepositoryDeployKeyAdd:
		return "audit.action.repository.deploykey.add"
	case RepositoryDeployKeyRemove:
		return "audit.action.repository.deploykey.remove"
	case RepositorySecretAdd:
		return "audit.action.repository.secret.add"
	case RepositorySecretUpdate:
		return "audit.action.repository.secret.update"
	case RepositorySecretRemove:
		return "audit.action.repository.secret.remove"

	case SystemStartup:
		return "audit.action.system.startup"
	case SystemShutdown:
		return "audit.action.system.shutdown"
	case SystemWebhookAdd:
		return "audit.action.system.webhook.add"
	case SystemWebhookUpdate:
		return "audit.action.system.webhook.update"
	case SystemWebhookRemove:
		return "audit.action.system.webhook.remove"
	case SystemAuthenticationSourceAdd:
		return "audit.action.system.authenticationsource.add"
	case SystemAuthenticationSourceUpdate:
		return "audit.action.system.authenticationsource.update"
	case SystemAuthenticationSourceRemove:
		return "audit.action.system.authenticationsource.remove"
	case SystemOAuth2ApplicationAdd:
		return "audit.action.system.oauth2application.add"
	case SystemOAuth2ApplicationUpdate:
		return "audit.action.system.oauth2application.update"
	case SystemOAuth2ApplicationSecret:
		return "audit.action.system.oauth2application.secret"
	case SystemOAuth2ApplicationRemove:
		return "audit.action.system.oauth2application.remove"

	default:
		panic("unknown audit action: " + a)
	}
}
