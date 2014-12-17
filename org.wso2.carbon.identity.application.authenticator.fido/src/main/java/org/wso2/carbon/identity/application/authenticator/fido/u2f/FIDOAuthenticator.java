/*
 * Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.application.authenticator.fido.u2f;

import org.apache.axis2.context.ConfigurationContext;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.utils.FIDOAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.fido.u2f.utils.FIDOClient;
import org.wso2.carbon.ui.CarbonUIUtil;
import org.wso2.carbon.utils.ServerConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * FIDO U2F Specification based authentication.
 */
public class FIDOAuthenticator extends AbstractApplicationAuthenticator implements
                                                                        LocalApplicationAuthenticator {

	private static FIDOClient client = null;

	@Override public AuthenticatorFlowStatus process(HttpServletRequest request,
	                                                 HttpServletResponse response,
	                                                 AuthenticationContext context)
			throws AuthenticationFailedException, LogoutFailedException {
		return super.process(request, response, context);
	}

	@Override protected void processAuthenticationResponse(
			HttpServletRequest request,
			HttpServletResponse response,
			AuthenticationContext authenticationContext) throws AuthenticationFailedException {
		String tokenResponse = request.getParameter("tokenResponse");
		String appID = request.getServerName();
		String username = request.getParameter("username");
		try {
			initialiseFIDOClient(request);
			client.finishAuthentication(tokenResponse, username, appID);
		} catch (Exception e) {
			throw new AuthenticationFailedException(e.getMessage(), e);
		}
	}

	@Override public boolean canHandle(javax.servlet.http.HttpServletRequest httpServletRequest) {
		String tokenResponse = httpServletRequest.getParameter("tokenResponse");

		return null != tokenResponse;

	}

	@Override public String getContextIdentifier(
			javax.servlet.http.HttpServletRequest httpServletRequest) {
		return httpServletRequest.getParameter("sessionDataKey");
	}

	@Override public String getName() {
		return FIDOAuthenticatorConstants.AUTHENTICATOR_NAME;
	}

	@Override public String getFriendlyName() {
		return FIDOAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
	}

	@Override protected void initiateAuthenticationRequest(HttpServletRequest request,
	                                                       HttpServletResponse response,
	                                                       AuthenticationContext context)
			throws AuthenticationFailedException {
		String username = request.getParameter("username");
		String appID = request.getServerName();
		String registrationData;
		try {
			initialiseFIDOClient(request);

			registrationData = client.startAuthentication(username, appID);

			String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
			System.out.println(loginPage);
			String queryParams = FrameworkUtils
					.getQueryStringWithFrameworkContextId(context.getQueryParams(),
					                                      context.getCallerSessionKey(),
					                                      context.getContextIdentifier());

			response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
			                      + "&authenticators=" + getName() + "&deviceRegistration=" +
			                      registrationData);
		} catch (IOException e) {
			throw new AuthenticationFailedException(e.getMessage(), e);
		} catch (Exception e) {
			throw new AuthenticationFailedException(e.getMessage(), e);
		}
	}

	@Override protected boolean retryAuthenticationEnabled() {
		return false;
	}

	private static String getDeviceRegistration(String username, String appID,
	                                            HttpServletRequest request)
			throws Exception {
		String deviceRegistration = "";

		initialiseFIDOClient(request);
		deviceRegistration = client.getDeviceRegistration(username, appID);

		return deviceRegistration;
	}

	private static void initialiseFIDOClient(HttpServletRequest request) throws Exception {
		String serverURL =
				CarbonUIUtil.getServerURL(request.getServletContext(), request.getSession());
		ConfigurationContext configContext =
				(ConfigurationContext) request.getServletContext()
				                              .getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
		String cookie =
				(String) request.getSession().getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
		client = new FIDOClient(configContext, serverURL, cookie);

	}

}

