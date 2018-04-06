package com.csaa.lyft.web.interceptor;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.util.Properties;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.elasticsearch.client.transport.TransportClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.csaa.lyft.domain.UserData;
import com.csaa.lyft.utils.SAMLUtils;

@Component
public class RequestProcessingInterceptor extends HandlerInterceptorAdapter {
 
    private static final Logger log = Logger.getLogger(RequestProcessingInterceptor.class);
 
   // @Autowired
   // TransportClient elasticsearchClient ;
    
   // @Autowired
    //SearchProcess searchProcess;
    
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        request.setAttribute("startTime", System.currentTimeMillis());
		response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE");
		response.setHeader("Access-Control-Allow-Origin", "*");
		response.setHeader("X-FRAME-OPTIONS", "ALLOW");
        //if returned false, we need to make sure 'response' is sent
        HttpSession session = request.getSession();
		boolean authenticated = true;
		UserData userData = (UserData)session.getAttribute("userData");
		if (userData == null) {
			authenticated = false;
			String ssoReq = request.getParameter("SAMLResponse");
			if (ssoReq == null) {
				String requestURI = request.getRequestURI();
				String contextPath = "";
				if (request.getContextPath() != null) {
					contextPath = request.getContextPath();
				}
				String[] ignoreURLs = { contextPath + "/admin" }; // contextPath + "/sso" , contextPath  + "/sso.html", contextPath + "/WEB-INF/pages/sso.html"
				String[] staticResources = { ".js", ".css", ".png", ".jpeg", ".jpg", ".gif", ".ico" };
				if (requestURI != null) {
					for (String url : ignoreURLs) {
						if (requestURI.startsWith(url)) {
							authenticated = true;
							break;
						}
					}
					for (String ext : staticResources) {
						if (requestURI.endsWith(ext)) {
							authenticated = true;
							break;
						}
					}
				}
				if (!authenticated) {
					String redirectURL = getProperties().getProperty("sso.idp.url");
					String ssoRedirect="";
					if(redirectURL != null){
						String queryParam = request.getQueryString();
						if(queryParam!=null) ssoRedirect = redirectURL+request.getRequestURL()+"?"+ queryParam;
						else ssoRedirect = redirectURL+request.getRequestURL();
					} else {
						redirectURL = SAMLUtils.getSAMLRequest(request);
						String ssoHost = getProperties().getProperty("sso.host");
						if(ssoHost!=null){
							String[] urls = redirectURL.split("idp/SSO.saml2");
							ssoRedirect = ssoHost+"idp/SSO.saml2"+urls[1];
							redirectURL = ssoRedirect;
						}
						
						String subDomainHost = getProperties().getProperty("subdomain.host");
						if(subDomainHost != null && request.getRequestURL().toString().contains(subDomainHost)){
							String[] ssoParams =redirectURL.split("RelayState");
							ssoRedirect = ssoParams[1]+"RelayState="+subDomainHost;
						} 
					}
					response.sendRedirect(ssoRedirect);
				}
			} else {
				try {
					authenticated = true;
					userData = SAMLUtils.isValidSAMLResponse(request);
					session = request.getSession(true);
					session.setAttribute("userData", userData);
					//String userName = new ElasticSearchOperations().getUserName(elasticsearchClient, userData.getUserName());
					String userName = "";
					session.setAttribute("userName", userName);
					Cookie myCookie = new Cookie("userName", userName);
					response.addCookie(myCookie);
					String redirectURL = request.getParameter("RelayState");
					if(redirectURL!=null && !redirectURL.endsWith("acs")) response.sendRedirect(redirectURL);
				} catch (Exception e) {
					log.error(
							"Exception in preHandle method of RequestProcessingInterceptor Class",
							e);
				}
			}
		}
        return authenticated;
    }
 
    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
    	//log.info("Request URL::" + request.getRequestURL().toString()  + " Sent to Handler :: Current Time=" + System.currentTimeMillis());
        //we can add attributes in the modelAndView and use that in the view page
    }
 
    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
    	try{
    	long startTime = (Long) request.getAttribute("startTime");
    	if (request.getRequestURI().startsWith(request.getContextPath()+"/search")) {
    		log.info("Request URL::" + URLDecoder.decode(request.getRequestURL().toString() +"?q="+ request.getHeader("Referer").split("s=")[1],"UTF-8") +":: Time Taken=" + (System.currentTimeMillis() - startTime) + " ms");
    	} else if (request.getRequestURI().startsWith(request.getContextPath()+"/autocomplete")){
	        log.info("Request URL::" + URLDecoder.decode(request.getRequestURL().toString() +"?q="+ request.getParameter("q"),"UTF-8") +":: Time Taken=" + (System.currentTimeMillis() - startTime) + " ms");
    	}
    	 request.removeAttribute("startTime");
    	}catch(Exception e){}
    }
    
    private Properties getProperties() {
		Properties prop = new Properties();
		InputStream input = null;
		try {
			input = new FileInputStream(System.getProperty("catalina.home")+"/conf/ecs-application.properties");
    		prop.load(input);
		} catch (IOException ex) {
			ex.printStackTrace();
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
					log.error(e.getStackTrace());
				}
			}
		}
		return prop;
	}
 
}
