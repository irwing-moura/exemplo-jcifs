package br.com.sistel.exemplo.config;

import br.com.sistel.exemplo.filter.NtlmHttpFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class NtlmHttpFilterConfig {

    @Value("${jcifs.http.domainController}")
    private String domainController;

    @Value("${jcifs.netbios.wins}")
    private String netbiosWins;

    @Value("${jcifs.util.loglevel}")
    private String logLevel;

    @Value("${jcifs.smb.client.soTimeout}")
    private String timeout;

    @Bean
    @Primary
    public FilterRegistrationBean<NtlmHttpFilter> filterRegistrationBean() {
        FilterRegistrationBean<NtlmHttpFilter> registrationBean = new FilterRegistrationBean();
        NtlmHttpFilter ntlmHttpFilter = new NtlmHttpFilter();

        registrationBean.setFilter(ntlmHttpFilter);
        registrationBean.setOrder(1);  //set precedence
        registrationBean.addUrlPatterns("/*");

        registrationBean.addInitParameter("jcifs.http.domainController", domainController);
        registrationBean.addInitParameter("jcifs.netbios.wins", netbiosWins);
        registrationBean.addInitParameter("jcifs.util.loglevel", logLevel);
        registrationBean.addInitParameter("jcifs.smb.client.soTimeout", timeout);

        return registrationBean;
    }
}

