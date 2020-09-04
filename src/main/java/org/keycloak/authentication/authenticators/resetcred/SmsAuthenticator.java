package org.keycloak.authentication.authenticators.resetcred;

import com.google.zxing.common.StringUtils;
import org.keycloak.authentication.actiontoken.DefaultActionTokenKey;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.*;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class SmsAuthenticator implements Authenticator, AuthenticatorFactory {

    private static final Logger logger = Logger.getLogger(SmsAuthenticator.class);

    public static final String PROVIDER_ID = "sms-authenticator";

    // 配置项
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("cookie.max.age");
        property.setLabel("Cookie Max Age");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Max age in seconds of the SECRET_QUESTION_COOKIE.");
        configProperties.add(property);
    }

    // 验证结果枚举
    private static enum CODE_STATUS {
        VALID,
        INVALID,
        EXPIRED
    }

    // 认证流程
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // 跳转输入验证码页面
        Response challenge = context.form().createForm("sms-validation.ftl");
        context.challenge(challenge);
    }

    // 表单提交处理
    @Override
    public void action(AuthenticationFlowContext context) {
        Response challenge = null;
        CODE_STATUS status = validateCode(context);
        switch (status){
            case INVALID:
                challenge =  context.form()
                        .setError("code is INVALID")
                        .createForm("sms-validation.ftl");
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
                break;

            case VALID:
                context.success();
                break;
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    // 在列表展示的名称
    @Override
    public String getDisplayType() {
        return "Send SMS";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    // 帮助信息
    @Override
    public String getHelpText() {
        return "通过发送短信验证码找回密码";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void close() {

    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    // 生成验证码
    private String createSmsCode() {
        //1000-9999之间的四位验证码
        Random random = new Random();
        int code = random.nextInt(9999-1000+1)+1000;
        return String.valueOf(code);
    }

    // 存储验证码
    private void storeSmsCode(AuthenticationFlowContext context, String code, Long expiringAt) {
        UserCredentialManager userCredentialManager = context.getSession().userCredentialManager();
        UserCredentialModel credentials = new UserCredentialModel();

        credentials.setType(SMSAuthenticatorContstants.USR_CRED_MDL_SMS_CODE);
        credentials.setValue(code);
        userCredentialManager.updateCredential(context.getRealm(), context.getUser(), credentials);

        credentials.setType(SMSAuthenticatorContstants.USR_CRED_MDL_SMS_EXP_TIME);
        credentials.setValue((expiringAt).toString());
        userCredentialManager.updateCredential(context.getRealm(), context.getUser(), credentials);

    }
    // 发送验证码

    // 校验验证码
    private CODE_STATUS validateCode(AuthenticationFlowContext context) {
        CODE_STATUS result = CODE_STATUS.INVALID;

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String enteredCode = formData.getFirst("smsCode");

        if (enteredCode.equals("123")) {
            result = CODE_STATUS.VALID;
        }
        return  result;
    }
}
