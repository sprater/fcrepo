package edu.virginia.lib.ole;

import java.io.IOException;

import java.security.Principal;

import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.kerberos.KerberosPrincipal;
//import org.fcrepo.server.security.servletfilters.Principal;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.fcrepo.server.security.jaas.auth.AuthHttpServletRequestWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author ajs6f
 * @author cs2@st-andrews.ac.uk
 */
public class AuthZHttpRequestAttributesFilter implements Filter {
	 
	 // names of HTTP headers to aggregate HTTP attribute
	 private Set<String> names;
	 
	 // name of the Shibboleth header that contains the principal's name
	 private String principalHeader;

	 // attribute in which to store authN data
	 private static final String FEDORA_ATTRIBUTES_KEY = "FEDORA_AUX_SUBJECT_ATTRIBUTES";
	 
	 private static final Logger logger = LoggerFactory.getLogger(AuthZHttpRequestAttributesFilter.class);

	 /** setNames
		* set the list of attribute names to look for
		* @param names, a String containing space separated attribute names
		* @return void
		*/
	 public void setNames(String names) //{{{
		 {
				this.names = new HashSet<String>(Arrays.asList(names.split(" ")));
		 }
	 //}}}
	 
	 /** setPrincipalHeader
		* set the name of the Shibboleth header whgich contains the principal's name
		* @param principalHeader, String containing name of header containing principal's name
		* @return void
		*/
	 public void setPrincipalHeader(String principalHeader) //{{{
		 {
				this.principalHeader = principalHeader;
		 }
	 //}}}

	 /** destroy
		* called when filter is destroyed, doesn't do anything
		* @param none
		* @return void
		*/
	 public void destroy() //{{{
		 {
				if (logger.isDebugEnabled()) {
					 logger.debug("AggregateHeadersFilter destroyed");
				}
		 }
	 //}}}
	 
	 public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
		 throws IOException, ServletException //{{{
		 { 
        HttpServletRequest req = (HttpServletRequest) request;
				
				// this is the map we will actually store into the request attribute
				Map<String, String[]> shibattributes = new HashMap<String, String[]>();
				
				// we use two loops to populate shibattributes in case we have multiple
				// homonymic headers in addition to multivalued headers
				for (String name : names) 
					{
						 Set<String> headervalues = new HashSet<String>();
						 for (Enumeration<String> retrievedheadervalues = req.getHeaders(name); retrievedheadervalues.hasMoreElements();) 
							 {
									String value = retrievedheadervalues.nextElement();
									
									if (logger.isDebugEnabled()) 
										{
											 logger.debug("Now adding value: " + value + " to field " + name);
										}
									
									headervalues.add(value);
							 }
						 // convert headervalues to a String[] and store it
						 shibattributes.put(name, headervalues.toArray(new String[0])); 
					}
				
				String[] principalname = shibattributes.get(principalHeader);
				AuthHttpServletRequestWrapper authRequest = null;
				boolean authenticated = false;
				
				do 
					{
						 // no principal name found
						 if (0 == principalname.length) 
							 {
									break;
							 }
						 
						 // more than one principal name found
						 if (principalname.length > 1) 
							 {
									logger.error(new Exception("More than one Shibboleth principal found in request!").toString());
									break;
							 }
						 
						 // make sure that first principal name is not empty
						 if (null == principalname[0] || 0 == principalname[0].length()) 
							 {
									break;
							 }
						 
						 // we'll try to set the appropriate member of the request 
						 if (logger.isDebugEnabled()) 
							 {
									logger.debug("Trying to set principal to new Principal with name=" + principalname[0]);
							 }
						 
						 // we use here the Fedora implementation of java.security.Principal
						 try 
							 { 
									// get name of principal and inject it into request
									KerberosPrincipal principal = new KerberosPrincipal(principalname[0]);
									//Principal principal = new Principal(principalname[0]);
									authRequest = new AuthHttpServletRequestWrapper(req);
									authRequest.setUserPrincipal((Principal) principal);
									
									if (logger.isDebugEnabled()) 
										{
											 logger.debug("Set principal to " + principal.toString());
										}
									
									// can inject other attributes
									authRequest.setAttribute(FEDORA_ATTRIBUTES_KEY, shibattributes);
									if (logger.isDebugEnabled()) 
										{
											 logger.debug("Adding " + shibattributes + " to " + FEDORA_ATTRIBUTES_KEY);
										}
							 }
						 catch (Exception e) 
							 {
									if (logger.isErrorEnabled()) 
										{
											 logger.error(e.toString());
										}
									
									break;
							 }
						 
						 authenticated = true;
					}
				while (false);
				
				if (authenticated && null != authRequest) 
					{
						 // pass on authenticated request to rest of chain
						 chain.doFilter(authRequest, response);
					}
				else 
					{
						 // not authenticated, so just pass original request through to rest of chain
						 chain.doFilter(request, response);
					}
		 }
	 //}}}

	 /** init
		* initialise filter
		* @param config FilterConfig object, not used
		* @return void
		*/
	 public void init(FilterConfig config) throws ServletException  //{{{
		 {
				this.init();
		 }
	 //}}}

	 /** init
		* initialise filter
		* @param none
		* @return void
		*/
	 public void init() throws ServletException //{{{
		 {
				// add principal header to list of names to look for
				names.add(principalHeader);
				
				// log initialisation
				if (logger.isInfoEnabled()) 
					{
						 logger.info("Initializing AggregateHeadersFilter");
					}
		 }
	 //}}}
	 
}
