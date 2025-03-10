"""
Generic Backend

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

from .handlers import admin, authentification, events, apiToken, email, files, frontpage, organizations, statistics, testResponse, files, users
from Benchy.BenchyMcMarkface import startFromDjango

newPaths = { 
    "landingPage": ("",frontpage.landingPage),
    "benchyPage": ("private/test/benchy/",frontpage.benchyPage),
    "benchyMcMarkface": ("private/test/benchyMcMarkface/",startFromDjango),
    
    "schema": ('public/api/schema/', SpectacularAPIView.as_view(api_version='0.3')),
    "swagger-ui": ('public/api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema')),

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
    "getAPIToken": ("public/auth/api-key/get/", apiToken.getAPIToken),
    "generateAPIToken": ("public/auth/api-key/create/", apiToken.generateAPIToken),
    "deleteAPIToken": ("public/auth/api-key/delete/", apiToken.deleteAPIToken),
    
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
    "adminDelete": ("public/admin/user/delete/<str:userHashedID>/",admin.deleteUserAsAdmin),
    "adminDeleteOrga": ("public/admin/organization/delete/<str:orgaHashedID>/",admin.deleteOrganizationAsAdmin),
    "adminUpdateUser": ("public/admin/user/update",admin.updateDetailsOfUserAsAdmin),
    "adminUpdateOrga": ("public/admin/organization/update/",admin.updateDetailsOfOrganizationAsAdmin),

    "getAllEventsForUser": ("public/events/all/get/", events.getAllEventsForUser),
    "getOneEventOfUser": ("public/events/get/<str:eventID>/", events.getOneEventOfUser),
    "createEvent": ("public/events/post/", events.createEvent),
    "deleteOneEvent": ("public/events/delete/<str:eventID>/", events.deleteOneEvent),
    "deleteAllEventsForAUser": ("public/events/all/delete/", events.deleteAllEventsForAUser),
    

    #"addOrga": ("private/profile_addOrga/",organizations.addOrganizationTest),
    "getOrganization": ("public/organizations/get/",organizations.getOrganizationDetails),
    "updateDetailsOfOrga": ("public/organizations/update/",organizations.updateDetailsOfOrganization),
    "deleteOrganization": ("public/organizations/delete/",organizations.deleteOrganization),
    "organizationsAddUser": ("public/organizations/users/add/",organizations.organizationsAddUser),
    "organizationsGetInviteLink": ("public/organizations/users/inviteLink/",organizations.organizationsGetInviteLink),
    "organizationsFetchUsers": ("public/organizations/users/get/",organizations.organizationsFetchUsers),
    "organizationsFetchInvitees": ("public/organizations/invites/get/",organizations.organizationsFetchInvitees),
    "organizationsDeleteInvite": ("public/organizations/invites/delete/<str:invitationID>/",organizations.organizationsDeleteInvite),
    "organizationsDeleteUser": ("public/organizations/users/delete/<str:userEMail>/",organizations.organizationsDeleteUser),
    "organizationsCreateRole": ("public/organizations/roles/create/",organizations.organizationsCreateRole),
    "organizationsGetRoles": ("public/organizations/roles/get/",organizations.organizationsGetRoles),
    "organizationsAssignRole": ("public/organizations/roles/assign/",organizations.organizationsAssignRole),
    "organizationsRemoveRole": ("public/organizations/roles/remove/",organizations.organizationsRemoveRole),
    "organizationsEditRole": ("public/organizations/roles/edit/",organizations.organizationsEditRole),
    "organizationsDeleteRole": ("public/organizations/roles/delete/<str:roleID>/",organizations.organizationsDeleteRole),
    "organizationsGetPermissions": ("public/organizations/permissions/get/",organizations.organizationsGetPermissions),
    "organizationsGetPermissionsForRole": ("public/organizations/permissions/role/get/<str:roleID>/",organizations.organizationsGetPermissionsForRole),
    "organizationsSetPermissionsForRole": ("public/organizations/permissions/role/set/",organizations.organizationsSetPermissionsForRole),
    "organizationsCreateOrganization": ("public/organizations/create/",organizations.organizationsCreateNewOrganization),

    "statistics": ("public/statistics/get/",statistics.getNumberOfUsers),

    "contactForm": ("public/contact/",email.sendContactForm),

    ########################## API ##############################
    "apiTest": ('public/api/test/',testResponse.testResponse),
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