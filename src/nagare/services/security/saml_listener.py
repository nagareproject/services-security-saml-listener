# Encoding: utf-8

# --
# Copyright (c) 2008-2024 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

from nagare.services import plugin
from nagare.sessions import common


class Service(plugin.Plugin):
    LOAD_PRIORITY = common.SessionsSelection.LOAD_PRIORITY - 1

    def __init__(self, name, dist, services_service, **config):
        services_service(super(Service, self).__init__, name, dist, **config)
        self.saml_services = {}

    def register_service(self, ident, saml_service):
        self.saml_services[ident] = saml_service

    def handle_request(self, chain, request, **params):
        state = request.params.get('RelayState')

        if state and state.startswith('#') and ('SAMLResponse' in request.params):
            saml_service_ident = state.split('#')[1]
            saml_service = self.saml_services.get(saml_service_ident)
            if saml_service is not None:
                is_valid, session_id, state_id = saml_service.is_auth_response(request)[:3]
                if is_valid:
                    params['session_id'] = session_id
                    params['state_id'] = state_id

                    request.is_authenticated = True

        return chain.next(request=request, **params)
