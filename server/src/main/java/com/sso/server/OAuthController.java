package com.sso.server;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Controller
@SessionAttributes({"authorizationRequest"})
public class OAuthController {
    @RequestMapping({"/oauth/approvale/confirm"})
    public String getAccessConfirmation(Map<String, Object> model,
                                        HttpServletRequest request) throws Exception {
        AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get("authorizationRequest");
        System.out.println(authorizationRequest.getScope());
        System.out.println( authorizationRequest.getClientId());
        return "oauth_approval";
    }

    @RequestMapping({"/oauth/approvale/error"})
    public String handleError(Map<String, Object> model, HttpServletRequest request) {
        Object error = request.getAttribute("error");
        String errorSummary;
        if (error instanceof OAuth2Exception) {
            OAuth2Exception oauthError = (OAuth2Exception) error;
            errorSummary = HtmlUtils.htmlEscape(oauthError.getSummary());
        } else {
            errorSummary = "Unknown error";
        }
        model.put("errorSummary", errorSummary);
        return "oauth_error";
    }
    //    @RequestMapping("/oauth/confirm_access")
//    public ModelAndView getAccessConfirmation(Map<String, Object> model, HttpServletRequest request) throws Exception {
//        AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get("authorizationRequest");
//        ModelAndView view = new ModelAndView();
//        view.setViewName("base-grant");
//        view.addObject("clientId", authorizationRequest.getClientId());
//        return view;
//    }
}