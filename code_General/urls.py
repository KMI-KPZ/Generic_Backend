"""
Part of Semper-KI software

Silvio Weging 2023

Contains: URL Configuration for code_General

"""

from django.urls import path, re_path
from django.conf import settings
from django.conf.urls import handler404

from main.urls import paths, urlpatterns, websockets
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

##############################################################################
### WSGI

from .handlers import admin, authentification, email, files, frontpage, organizations, statistics, testResponse, files, users
from Benchy.BenchyMcMarkface import startFromDjango

newPaths = { 
    "landingPage": ("",frontpage.landingPage),
    "benchyPage": ("private/test/benchy/",frontpage.benchyPage),
    "benchyMcMarkface": ("private/test/benchyMcMarkface/",startFromDjango),
    
    "schema": ('api/schema/', SpectacularAPIView.as_view(api_version='0.3')),
    "swagger-ui": ('api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema')),

    "test": ('public/test/',testResponse.testResponse),
    "csrfTest": ('public/test/csrf/',testResponse.testResponseCsrf),
    "dynamicTest": ('private/test/dynamic/',testResponse.dynamic),
    
    "login" : ("public/auth/login/",authentification.loginUser),
    "csrfCookie": ('public/auth/csrfCookie/',authentification.createCsrfCookie),
    "loginAsTestUser": ("private/auth/login/testUser/", authentification.loginAsTestUser),
    "logout": ("public/auth/logout/",authentification.logoutUser),
    "callbackLogin": ("public/auth/callback/",authentification.callbackLogin),
    "isLoggedIn": ("public/auth/isLoggedIn/",authentification.isLoggedIn),
    "getRoles": ("public/auth/roles/get/",authentification.getRolesOfUser),
    "getPermissions": ("public/auth/permissions/get/",authentification.getPermissionsOfUser),
    "getNewPermissions": ("public/auth/permissions/new/get/",authentification.getNewRoleAndPermissionsForUser),
    "getPermissionsFile": ("public/auth/permissions/mask/get/",authentification.provideRightsFile),
    "setLocaleOfUser": ("public/auth/localeOfUser/set/", authentification.setLocaleOfUser),

    "deleteUser": ("public/profile/user/delete/",users.deleteUser),
    #"addUser": ("private/profile_addUser/",profiles.addUserTest),
    
    "getUser": ("public/profile/user/get/",users.getUserDetails),
    "updateDetails": ("public/profile/user/update/",users.updateDetails),
    #"createAddress": ("public/profile/address/create/", users.createAddress),
    #"updateAddress": ("public/profile/address/update/", users.updateAddress),
    #"deleteAddress": ("public/profile/address/delete/<str:addressID>/", users.deleteAddress),
    
    "genericUploadFiles": ("private/generic/files/upload/",files.genericUploadFiles),
    "genericDownloadFile": ("private/generic/files/download/",files.genericDownloadFile),
    "genericDownloadFilesAsZip": ("private/generic/files/download/asZip/",files.genericDownloadFilesAsZip),
    "genericDeleteFile": ("private/generic/files/delete/",files.genericDeleteFile),

    "adminGetAll": ("public/admin/all/get/",admin.getAllAsAdmin),
    "adminDelete": ("public/admin/user/delete/<str:userHashedID>",admin.deleteUserAsAdmin),
    "adminDeleteOrga": ("public/admin/organization/delete/<str:orgaHashedID>/",admin.deleteOrganizationAsAdmin),
    "adminUpdateUser": ("public/admin/user/update",admin.updateDetailsOfUserAsAdmin),
    "adminUpdateOrga": ("public/admin/organization/update/",admin.updateDetailsOfOrganizationAsAdmin),

    #"addOrga": ("private/profile_addOrga/",organizations.addOrganizationTest),
    "getOrganization": ("public/organizations/get/",organizations.getOrganizationDetails),
    "updateDetailsOfOrga": ("public/organizations/update/",organizations.updateDetailsOfOrganization),
    "deleteOrganization": ("public/organizations/delete/",organizations.deleteOrganization),
    "organizations_addUser": ("public/organizations/users/add/",organizations.organizations_addUser),
    "organizations_getInviteLink": ("public/organizations/users/inviteLink/",organizations.organizations_getInviteLink),
    "organizations_fetchUsers": ("public/organizations/users/get/",organizations.organizations_fetchUsers),
    "organizations_fetchInvitees": ("public/organizations/invites/get/",organizations.organizations_fetchInvitees),
    "organizations_deleteInvite": ("public/organizations/invites/delete/<str:invitationID>/",organizations.organizations_deleteInvite),
    "organizations_deleteUser": ("public/organizations/users/delete/<str:userEMail>/",organizations.organizations_deleteUser),
    "organizations_createRole": ("public/organizations/roles/create/",organizations.organizations_createRole),
    "organizations_getRoles": ("public/organizations/roles/get/",organizations.organizations_getRoles),
    "organizations_assignRole": ("public/organizations/roles/assign/",organizations.organizations_assignRole),
    "organizations_removeRole": ("public/organizations/roles/remove/",organizations.organizations_removeRole),
    "organizations_editRole": ("public/organizations/roles/edit/",organizations.organizations_editRole),
    "organizations_deleteRole": ("public/organizations/roles/delete/<str:roleID>/",organizations.organizations_deleteRole),
    "organizations_getPermissions": ("public/organizations/permissions/get/",organizations.organizations_getPermissions),
    "organizations_getPermissionsForRole": ("public/organizations/permissions/role/get/<str:roleID>/",organizations.organizations_getPermissionsForRole),
    "organizations_setPermissionsForRole": ("public/organizations/permissions/role/set/",organizations.organizations_setPermissionsForRole),
    "organizations_createOrganization": ("public/organizations/create/",organizations.organizations_createNewOrganization),

    "statistics": ("public/statistics/get/",statistics.getNumberOfUsers),

    "contactForm": ("public/contact/",email.sendContactForm),
}

paths.update(newPaths)

urlpatterns.extend([
    re_path(r'^private/doc', frontpage.docPage, name="docPage"),
    
    path('private/test/', testResponse.testResponse, name='test_response'),
    path('private/testWebsocket/', testResponse.testCallToWebsocket, name='testCallToWebsocket'),
])

if settings.DEBUG:
    urlpatterns.append(path('private/settings/', testResponse.getSettingsToken, name='getSettingsToken'))

# add paths
for entry in newPaths:
    key = entry
    pathTuple = newPaths[entry]
    pathItself = pathTuple[0]
    handler = pathTuple[1]
    urlpatterns.append(path(pathItself, handler, name=key))

# any illegitimate requests are given a fu and their ip will be logged. Works only if DEBUG=False
handler404 = statistics.getIpAddress

##############################################################################
### ASGI
from .handlers.websocket import GeneralWebSocket

websockets.append(
    path("ws/generalWebsocket/", GeneralWebSocket.as_asgi(), name="Websocket")
)