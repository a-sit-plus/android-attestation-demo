package com.example.attestationservice

import com.example.lib.LevelOfTrust
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.core.env.Environment
import org.springframework.core.env.Profiles
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter

@Configuration
class WebSecurityConfiguration : WebSecurityConfigurerAdapter() {

    @Autowired
    private lateinit var userDetailsService: AttestedUserDetailsService

    @Autowired
    private lateinit var environment: Environment

    private val roleLotUnknown = "LOT_${LevelOfTrust.UNKNOWN.name}"
    private val roleLotLow = "LOT_${LevelOfTrust.LOW.name}"
    private val roleLotMedium = "LOT_${LevelOfTrust.MEDIUM.name}"
    private val roleLotHigh = "LOT_${LevelOfTrust.HIGH.name}"

    override fun configure(http: HttpSecurity) {
        http.csrf().disable()
                .cors().disable()
                .authorizeRequests()
                .antMatchers("/").anonymous()
                .antMatchers("/bind").hasRole(roleLotUnknown)
                .antMatchers("/lot/high").hasRole(roleLotHigh)
                .antMatchers("/lot/medium").hasAnyRole(roleLotMedium, roleLotHigh)
                .antMatchers("/lot/low").hasAnyRole(roleLotLow, roleLotMedium, roleLotHigh)
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        if (environment.acceptsProfiles(Profiles.of("reverseproxy"))) {
            val filter = RequestHeaderAuthenticationFilter().apply {
                setPrincipalRequestHeader("SSL_CLIENT_CERT")
                setAuthenticationManager(authenticationManager())
            }
            http.addFilterBefore(filter, X509AuthenticationFilter::class.java)
        } else {
            http.x509().authenticationUserDetailsService(userDetailsService)
        }
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
        val provider = PreAuthenticatedAuthenticationProvider().apply {
            setPreAuthenticatedUserDetailsService(userDetailsService)
        }
        auth.authenticationProvider(provider).eraseCredentials(true)
    }

}

