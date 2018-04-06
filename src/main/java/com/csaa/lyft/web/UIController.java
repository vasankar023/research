/**
 * 
 * @author VasanthKarthik Jayaraman
 * Apr 5, 2018
 * UIController.java
 *
 **/

package com.csaa.lyft.web;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class UIController {
	Logger log = Logger.getLogger(UIController.class);
	
	@RequestMapping(value = "/home", method = RequestMethod.GET)
	public String goHome() {
		System.out.println("I am inside home action..........................");
		return "home";
	}
	
	@RequestMapping(value = "/acs", method = RequestMethod.POST)
	public String searchHome(@RequestParam("SAMLResponse") String samlResponse, @RequestParam("RelayState") String relaystate) {
		return "redirect:/";
	}

}
