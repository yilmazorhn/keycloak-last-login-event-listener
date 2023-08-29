package com.vodafone.acq.event;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

public class LastLoginEventListenerProvider  implements EventListenerProvider {

    private static final String LAST_LOGIN_ATTRIBUTE_NAME = "lastLogin";
    private static final String LAST_LOGIN_ATTRIBUTE_TOKEN_NAME = "prior_login";

    private final KeycloakSession session;
    private final RealmProvider model;

    public LastLoginEventListenerProvider(KeycloakSession session) {
        this.session = session;
        this.model = session.realms();
    }

    @Override
    public void onEvent(Event event) {
        if (EventType.LOGIN.equals(event.getType())) {
            RealmModel realm = this.model.getRealm(event.getRealmId());
            UserModel user = this.session.users().getUserById(event.getUserId(), realm);

            if (user != null) {

                Map<String, List<String>> userAttrs = user.getAttributes();
                if (userAttrs.containsKey(LAST_LOGIN_ATTRIBUTE_NAME)) {
                    List<String> userLastLogin = userAttrs.get(LAST_LOGIN_ATTRIBUTE_NAME);
                    if (userLastLogin != null && !userLastLogin.isEmpty()) {
                        user.setSingleAttribute(LAST_LOGIN_ATTRIBUTE_TOKEN_NAME, userLastLogin.get(0));
                    }
                }

                OffsetDateTime loginTime = OffsetDateTime.now(ZoneOffset.UTC);
                String loginTimeS = DateTimeFormatter.ISO_DATE_TIME.format(loginTime);
                user.setSingleAttribute(LAST_LOGIN_ATTRIBUTE_NAME, loginTimeS);
            }
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean b) {
    }

    @Override
    public void close() {
    }
}
