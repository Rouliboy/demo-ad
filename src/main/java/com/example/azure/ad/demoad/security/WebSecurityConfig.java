package com.example.azure.ad.demoad.security;

// @Component
// @EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
// public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
//
// @Autowired
// private AADAuthenticationFilter aadAuthFilter;
//
// @Override
// protected void configure(final HttpSecurity http) throws Exception {
//
// http.authorizeRequests().antMatchers("/home").permitAll();
// http.authorizeRequests().antMatchers("/api/**").authenticated();
//
// http.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/")
// .deleteCookies("JSESSIONID").invalidateHttpSession(true);
//
// http.authorizeRequests().anyRequest().permitAll();
//
// http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
//
// http.addFilterBefore(aadAuthFilter, UsernamePasswordAuthenticationFilter.class);
// }
// }
