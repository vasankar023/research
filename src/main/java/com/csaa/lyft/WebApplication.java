/**
 * 
 * @author VasanthKarthik Jayaraman
 * Apr 5, 2018
 * WebApplication.java
 *
 **/

package com.csaa.lyft;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.embedded.ErrorPage;
import org.springframework.boot.context.web.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

//import com.csaa.lyft.utils.SAMLUtils;

@Configuration
@EnableAutoConfiguration
@ComponentScan
@ImportResource("classpath:lyft-servlet.xml")
public class WebApplication extends SpringBootServletInitializer {
	
	Logger log = Logger.getLogger(WebApplication.class);
	private final static String HTML_PAGES_PATH = "/WEB-INF/pages/";

	@Override
	protected SpringApplicationBuilder  configure(SpringApplicationBuilder application) {
		return application.sources(WebApplication.class);
	}
	
	@Override
	  public void onStartup (final ServletContext servletContext) throws ServletException {
	    super.onStartup( servletContext );
	   /* File file = new File(System.getProperty("catalina.home")+"/conf/sso/idp_metadata.xml");
		FileInputStream fis = null;
		
		try {
			
			fis = new FileInputStream(file.getCanonicalFile());
			SAMLUtils.readIDPMetaData(fis);
			try {
				fis.close();
			} catch (IOException e) {
				log.error("Exception in reading IDP Metadata",e);
			}
			
			file = new File(System.getProperty("catalina.home")+"/conf/sso/serviceprovider.properties");
			fis = new FileInputStream(file.getCanonicalFile());
			SAMLUtils.readSPMetaData(fis);
			try {
				fis.close();
			} catch (IOException e) {
				log.error("Exception in reading SP Metadata",e);
			}
		} catch (IOException e) {
			log.error("Exception in reading Metadata",e);
		}*/
	  }
	
	
	/***
	 * 
	 * The following sub class in created to restrict admin access to the
	 * specified users.
	 * 
	 */

	@Configuration
	@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
	protected static class ApplicationSecurity extends
			WebSecurityConfigurerAdapter {

		@Autowired
		private SecurityProperties security;

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication().withUser("admin").password("EcsPr0d@dm1n").roles("ADMIN");
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.csrf().disable().authorizeRequests().antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')").and().formLogin();
		}

	}

	/**
	 * The following for WebMVC flow for application to configure the
	 * properties.
	 * 
	 * 
	 */

	@Configuration
	@EnableWebMvc
	public static class ApplicationConfigurerAdapter extends WebMvcConfigurerAdapter {

		@Override
		public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
			configurer.enable();
		}

		@Bean
		public InternalResourceViewResolver viewResolver() {
			InternalResourceViewResolver resolver = new InternalResourceViewResolver();
			resolver.setPrefix(HTML_PAGES_PATH);
			resolver.setSuffix(".html");
			return resolver;
		}
	}

    @Bean
    public EmbeddedServletContainerCustomizer containerCustomizer() {

        return new EmbeddedServletContainerCustomizer() {
            @Override
            public void customize(ConfigurableEmbeddedServletContainer container) {
            	ErrorPage error400Page = new ErrorPage(HttpStatus.BAD_REQUEST, HTML_PAGES_PATH + "500.html");
            	ErrorPage error401Page = new ErrorPage(HttpStatus.UNAUTHORIZED, HTML_PAGES_PATH + "401.html");
                ErrorPage error404Page = new ErrorPage(HttpStatus.NOT_FOUND, HTML_PAGES_PATH + "404.html");
                ErrorPage error500Page = new ErrorPage(HttpStatus.INTERNAL_SERVER_ERROR, HTML_PAGES_PATH + "500.html");
                container.addErrorPages(error400Page, error401Page, error404Page, error500Page);
            }
        };
    }

	public static void main(String[] args) throws Exception {
		SpringApplication app = new SpringApplication(WebApplication.class); 
        app.setShowBanner(true);
        app.run(args);
	}

}
