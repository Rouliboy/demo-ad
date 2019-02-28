package com.example.azure.ad.demoad.security;

// @Configuration
// @EnableResourceServer
// public class OAuth2ResourceServerConfig extends ResourceServerConfigurerAdapter {
// @Override
// public void configure(final ResourceServerSecurityConfigurer config) {
// config.tokenServices(tokenServices());
// }
//
// @Bean
// public TokenStore tokenStore() {
// return new JwtTokenStore(accessTokenConverter());
// }
//
// @Bean
// public JwtAccessTokenConverter accessTokenConverter() {
// final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
// converter.setVerifierKey(obtainAzureADPublicKey());
// return converter;
// }
//
// @Bean
// @Primary
// public DefaultTokenServices tokenServices() {
// final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
// defaultTokenServices.setTokenStore(tokenStore());
// return defaultTokenServices;
// }
// }
