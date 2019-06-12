package com.example.attestationservice

import com.example.lib.LevelOfTrust
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy

@Configuration
class WebSecurityConfiguration : WebSecurityConfigurerAdapter() {

    @Autowired
    private lateinit var userDetailsService: AttestedUserDetailsService

    private val roleLotUnknown = "LOT_${LevelOfTrust.UNKNOWN.name}"
    private val roleLotLow = "LOT_${LevelOfTrust.LOW.name}"
    private val roleLotMedium = "LOT_${LevelOfTrust.MEDIUM.name}"
    private val roleLotHigh = "LOT_${LevelOfTrust.HIGH.name}"

    override fun configure(http: HttpSecurity?) {
        http!!.csrf().disable()
                .cors().disable()
                .authorizeRequests()
                .antMatchers("/").anonymous()
                .antMatchers("/bind").hasRole(roleLotUnknown)
                .antMatchers("/lot/high").hasRole(roleLotHigh)
                .antMatchers("/lot/medium").hasAnyRole(roleLotMedium, roleLotHigh)
                .antMatchers("/lot/low").hasAnyRole(roleLotLow, roleLotMedium, roleLotHigh)
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().x509().authenticationUserDetailsService(userDetailsService)
    }

}

