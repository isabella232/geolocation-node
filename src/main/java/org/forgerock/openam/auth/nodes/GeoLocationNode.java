/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */


package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.RequiredValueValidator;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.*;

import java.io.*;
import java.net.*;
import java.time.Instant;
import java.time.Duration;
import java.util.*;

import javax.inject.Inject;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/**
 *
 * An authentication node which compares the login location to the previous login.
 *
 * Risk evaluation is based on absolute distances, required speed from last login location, country white/black lists, etc.
 *
 * @author Keith Daly - ForgeRock
 * @version 1.1.0
 *
 */
@Node.Metadata(outcomeProvider  = GeoLocationNode.GeoLocationOutcomeProvider.class,
               configClass      = GeoLocationNode.Config.class)
public class GeoLocationNode implements Node {

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "GeoLocationNode";
    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/GeoLocationNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    //-- 1xx --
    private static final int MODE_SAVE = 0;
    private static final int MODE_CHECK = 1;
    private int mode; //= MODE_SAVE;
    private String ipDataStoreField;

    //-- 2xx --
    private Provider provider;
    private String ipServiceURL;
    private String ipServiceAccessKey;

    //-- 3xx --
    private static final int MODE_IP_DIRECT = 0;
    private static final int MODE_IP_PROXY = 1;
    private static final int MODE_IP_SHARED_STATE = 2;
    private int modeIP = MODE_IP_DIRECT;
    private String proxyAttribute;

    //-- 4xx --
    private DistanceUnit distanceUnit;

    //-- 5xx --
    private boolean distanceRisk;
    private Double distanceNoRisk;
    private Double distanceLowRisk;
    private Double distanceModerateRisk;

    //-- 6xx --
    private boolean speedLimitRisk;
    private Double speedLimitNoRisk;
    private Double speedLimitLowRisk;
    private Double speedLimitModerateRisk;

    //-- 7xx --
    private CountryListType countryListType;
    private Set <String> countryWhiteList;
    private Set <String> countryBlackList;


    //-- Operational --
    AMIdentity userIdentity;
    String loginIP;
    String currentIP;

    Long distanceKilometers;
    Long distanceMiles;
    Double milesPerHour;
    Double kmPerHour;

    /**
     * Configuration for the node.
     */
    public interface Config {

        //-- 1xx - Node Config --

        //-- Operational mode - STORE or CHECK --
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        //default String nodeMode() { return "CHECK"; }
        default NodeMode nodeMode() { return NodeMode.CHECK; }

        //-- Attribute to store login IP information --
        @Attribute(order = 110, validators = {RequiredValueValidator.class})
        default String ipDataStoreField() {
            return "carLicense";
        }

        //-- 2xx - Service Config --

        //-- IP Data Service Provider
        @Attribute(order = 200)
        default Provider provider() { return Provider.IPAPI; }

        //-- Access key from service --
        @Attribute(order = 220, validators = {RequiredValueValidator.class})
        @Password
        char[] ipServiceAccessKey();

        //-- 3xx - Proxy Information

        //-- Proxy Mode - DIRECT or PROXY --
        @Attribute(order = 300)
        default ProxyMode proxyMode() { return ProxyMode.DIRECT; }

        //-- Proxy Header --
        @Attribute(order = 310)
        default String proxyAttribute() {
            return "x-forwarded-for";
        }

        //-- 4xx - Localization --

        //-- Localization - MILE or KM --
        @Attribute(order = 400)
        default DistanceUnit distanceUnit() { return DistanceUnit.MILE; }

        //-- 5xx - Distance Checks --

        @Attribute(order = 500)
        default boolean distanceRisk() {
            return false;
        }

        @Attribute(order = 510)
        default String distanceNoRisk() {
            return "30";
        }

        @Attribute(order = 520)
        default String distanceLowRisk() {
            return "50";
        }

        @Attribute(order = 530)
        default String distanceModerateRisk() {
            return "100";
        }

        //-- 6xx - Speed Limit Checks --

        @Attribute(order = 600)
        default boolean speedLimitRisk() {
            return false;
        }

        //-- Default - running (miles)
        @Attribute(order = 610)
        default String speedLimitNoRisk() {
            return "15";
        }

        //-- Default - car - (miles)
        @Attribute(order = 620)
        default String speedLimitLowRisk() {
            return "70";
        }

        //-- Default - plane - (miles)
        @Attribute(order = 630)
        default String speedLimitModerateRisk() {
            return "600";
        }

        //-- 7xx - Country Lists --

        @Attribute(order = 700)
        default CountryListType countryListType() {
            return CountryListType.NONE;
        }

        @Attribute(order = 710)
        Set<String> countryWhiteList();

        @Attribute(order = 720)
        Set<String> countryBlackList();

    }

    /**
     * Create the node.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public GeoLocationNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    /**
     * Main processing method
     *
     * CHECK will check distance, speed, etc., from last login.
     * CHECK will save current IP if none exits.
     * CHECK will save current IP if low risk and not the same IP.
     *
     * STORE will save current IP (used if risk is assumed after other checks).
     *
     * @param context
     * @return
     * @throws NodeProcessException
     */
    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        debug.message("[" + DEBUG_FILE + "]: GeoLocationNode::process()");
        Action.ActionBuilder action;
        JsonValue newState = context.sharedState.copy();

        int riskLevel = 0;

        //-- Load configuration from tree --
        loadConfig();

        //-- Set the identity object from the context --
        setIdentity(context);

        //-- Main section - CHECK or SAVE --
        switch (mode) {
            case MODE_SAVE:
                //-- Set the login IP and timestamp --
                //-- SAVE should only be used post assumed risk --
                setLoginIP(context);
                break;
            case MODE_CHECK:
                //-- Set the login IP and timestamp if empty --
                //-- Otherwise, compare locations

                try {
                    if (userIdentity.getAttribute(ipDataStoreField).isEmpty()) {

                        //-- No coordinates needed if no login data exists and no country lists in effect
                        if (countryListType == CountryListType.WHITE || countryListType == CountryListType.BLACK) {
                            setLoginIP(context);
                            setLoginIPCoordinates();
                        } else {
                            setLoginIP(context);
                        }

                        //-- Fail if black list & country on list, or white list and country not on list
                        if (countryListType == CountryListType.BLACK && checkLoginCountryOnBlackList()) {
                            debug.warning("[" + DEBUG_FILE + "]: HIGH RISK - Black list active and country on list");
                            action = goTo(GeoLocationOutcome.HIGH);
                        } else if (countryListType == CountryListType.WHITE && !(checkLoginCountryOnWhiteList())) {
                            debug.warning("[" + DEBUG_FILE + "]: HIGH RISK - White list active and country not on list");
                            action = goTo(GeoLocationOutcome.HIGH);
                        } else {
                            debug.warning("[" + DEBUG_FILE + "]: NO RISK");
                            action = goTo(GeoLocationOutcome.NONE);
                        }
                        return action.replaceSharedState(newState).build();

                    } else {

                        loadLoginIP();

                        //-- Fail if black list & country on list, or white list and country not on list
                        if (countryListType == CountryListType.BLACK && checkLoginCountryOnBlackList()) {
                            debug.warning("[" + DEBUG_FILE + "]: HIGH RISK - Black list active and country on list");
                            action = goTo(GeoLocationOutcome.HIGH);
                            return action.replaceSharedState(newState).build();
                        } else if (countryListType == CountryListType.WHITE && !(checkLoginCountryOnWhiteList())) {
                            debug.warning("[" + DEBUG_FILE + "]: HIGH RISK - White list active and country not on list");
                            action = goTo(GeoLocationOutcome.HIGH);
                            return action.replaceSharedState(newState).build();
                        }

                        setCurrentIP(context);

                        debug.message("[" + DEBUG_FILE + "]: " + " LOGIN : " + loginIP.split("::")[0]);
                        debug.message("[" + DEBUG_FILE + "]: " + " CURRENT : " + currentIP.split("::")[0]);

                        if (currentIP.split("::")[0].equals(loginIP.split("::")[0])) {
                            //-- No change in IP --> no risk --
                            debug.message("[" + DEBUG_FILE + "]: NO RISK : SAME IP");
                        } else {
                            setLoginIPCoordinates();
                            setCurrentIPCoordinates();

                            //-- Fail if black list & country on list, or white list and country not on list
                            if (countryListType == CountryListType.BLACK && checkCurrentCountryOnBlackList()) {
                                debug.warning("[" + DEBUG_FILE + "]: HIGH RISK - Black list active and country on list");
                                action = goTo(GeoLocationOutcome.HIGH);
                                return action.replaceSharedState(newState).build();
                            } else if (countryListType == CountryListType.WHITE && !(checkCurrentCountryOnWhiteList())) {
                                debug.warning("[" + DEBUG_FILE + "]: HIGH RISK - White list active and country not on list");
                                action = goTo(GeoLocationOutcome.HIGH);
                                return action.replaceSharedState(newState).build();
                            }

                            setDistanceFromLogin();
                            debug.message("[" + DEBUG_FILE + "]: " + "DIFFERENT IP");
                        }

                        //-- Check distance --
                        if (distanceRisk == true) {
                            debug.message("[" + DEBUG_FILE + "]: " + "DISTANCE");
                            if (distanceUnit.equals(DistanceUnit.KM)) {
                                if (distanceKilometers != null) {
                                    if (distanceKilometers > distanceModerateRisk) {
                                        debug.warning("[" + DEBUG_FILE + "]: DISTANCE HIGH RISK");
                                        riskLevel = 3;
                                    } else if (distanceKilometers > distanceLowRisk) {
                                        debug.warning("[" + DEBUG_FILE + "]: DISTANCE MODERATE RISK");
                                        if (riskLevel < 3) riskLevel = 2;
                                    } else if (distanceKilometers > distanceNoRisk) {
                                        debug.warning("[" + DEBUG_FILE + "]: DISTANCE LOW RISK");
                                        if (riskLevel < 2) riskLevel = 1;
                                    }
                                } else {
                                    debug.warning("[" + DEBUG_FILE + "]: DISTANCE IN KM = null. DISTANCE NO RISK");
                                    distanceKilometers = 0L;
                                    riskLevel = 0;
                                }
                            } else if (distanceUnit.equals(DistanceUnit.MILE)) {
                                if (distanceMiles != null) {
                                    if (distanceMiles > distanceModerateRisk) {
                                        debug.warning("[" + DEBUG_FILE + "]: DISTANCE HIGH RISK");
                                        riskLevel = 3;
                                    } else if (distanceMiles > distanceLowRisk) {
                                        debug.warning("[" + DEBUG_FILE + "]: DISTANCE MODERATE RISK");
                                        if (riskLevel < 2) riskLevel = 2;
                                    } else if (distanceMiles > distanceNoRisk) {
                                        debug.warning("[" + DEBUG_FILE + "]: DISTANCE LOW RISK");
                                        if (riskLevel < 2) riskLevel = 1;
                                    }
                                } else {
                                    debug.warning("[" + DEBUG_FILE + "]: DISTANCE IN MILES = null. DISTANCE NO RISK");
                                    distanceMiles = 0L;
                                    riskLevel = 0;
                                }
                            }
                        }

                        //-- Check speed --
                        if (speedLimitRisk == true) {
                            debug.message("[" + DEBUG_FILE + "]: " + "SPEED");
                            if (distanceUnit.equals(DistanceUnit.KM)) {
                                if (kmPerHour != null) {
                                    if (kmPerHour > speedLimitModerateRisk) {
                                        debug.warning("[" + DEBUG_FILE + "]: SPEED HIGH RISK");
                                        riskLevel = 3;
                                    } else if (kmPerHour > speedLimitLowRisk) {
                                        debug.warning("[" + DEBUG_FILE + "]: SPEED MODERATE RISK");
                                        if (riskLevel < 3) riskLevel = 2;
                                    } else if (kmPerHour > speedLimitNoRisk) {
                                        debug.warning("[" + DEBUG_FILE + "]: SPEED LOW RISK");
                                        if (riskLevel < 2) riskLevel = 1;
                                    }
                                } else {
                                    debug.warning("[" + DEBUG_FILE + "]: SPEED IN KM = null. SPEED NO RISK");
                                    kmPerHour = 0.0;
                                    riskLevel = 0;
                                }
                            } else if (distanceUnit.equals(DistanceUnit.MILE)) {
                                if (milesPerHour > speedLimitModerateRisk) {
                                    if (milesPerHour != null) {
                                        debug.warning("[" + DEBUG_FILE + "]: SPEED HIGH RISK");
                                        riskLevel = 3;
                                    } else if (milesPerHour > speedLimitLowRisk) {
                                        debug.warning("[" + DEBUG_FILE + "]: SPEED MODERATE RISK");
                                        if (riskLevel < 3) riskLevel = 2;
                                    } else if (milesPerHour > speedLimitNoRisk) {
                                        debug.warning("[" + DEBUG_FILE + "]: SPEED LOW RISK");
                                        if (riskLevel < 2) riskLevel = 1;
                                    }
                                } else {
                                    debug.warning("[" + DEBUG_FILE + "]: SPEED IN MILES = null. SPEED NO RISK");
                                    milesPerHour = 0.0;
                                    riskLevel = 0;
                                }

                            }
                        }

                    }
                } catch (Exception e) {
                    debug.error("[" + DEBUG_FILE + "]: " + e);
                    action = goTo(GeoLocationOutcome.UNKNOWN);
                    return action.replaceSharedState(newState).build();
                }
                break;
        }

        if (riskLevel >  2) {
            debug.warning("[" + DEBUG_FILE + "]: HIGH RISK");
            action = goTo(GeoLocationOutcome.HIGH);
        } else if (riskLevel > 1) {
            debug.warning("[" + DEBUG_FILE + "]: MODERATE RISK");
            action = goTo(GeoLocationOutcome.MODERATE);
        } else if (riskLevel > 0) {
            debug.warning("[" + DEBUG_FILE + "]: LOW RISK");
            action = goTo(GeoLocationOutcome.LOW);
        } else {
            debug.warning("[" + DEBUG_FILE + "]: NO RISK");
            action = goTo(GeoLocationOutcome.NONE);
        }
        return action.replaceSharedState(newState).build();
    }

    private Action.ActionBuilder goTo(GeoLocationOutcome outcome) {
        return Action.goTo(outcome.name());
    }

    private void loadConfig() {

        //-- 1xx --
        NodeMode nodeMode = config.nodeMode();
        debug.message("[" + DEBUG_FILE + "]: nodeMode : " + nodeMode);
        switch (nodeMode) {
            case STORE:
                debug.message("[" + DEBUG_FILE + "]: mode is set to MODE_SAVE");
                mode = MODE_SAVE;
                break;
            case CHECK:
                debug.message("[" + DEBUG_FILE + "]: mode is set to MODE_CHECK");
                mode = MODE_CHECK;
                break;
            default:
                debug.message("[" + DEBUG_FILE + "]: mode not specified - default MODE_SAVE is used");
                mode = MODE_SAVE;
                break;
        }
        ipDataStoreField = config.ipDataStoreField();
        debug.message("[" + DEBUG_FILE + "]: ipDataStoreField : " + ipDataStoreField);

        //-- 2xx --
        provider = config.provider();
        debug.message("[" + DEBUG_FILE + "]: provider : " + provider);
        //ipServiceURL = config.ipServiceURL();
        //debug.message("[" + DEBUG_FILE + "]: ipServiceURL : " + ipServiceURL);
        switch (provider) {
            case IPAPI:
                ipServiceURL = "http://ip-api.com/json/";
                break;
            case IPSTACK:
                ipServiceURL = "http://api.ipstack.com/";
                break;
        }
        debug.message("[" + DEBUG_FILE + "]: Service URL : " + ipServiceURL);
        if (config.ipServiceAccessKey().length > 0) {
            ipServiceAccessKey = charToString(config.ipServiceAccessKey());
        } else {
            ipServiceAccessKey = "";
        }
        debug.message("[" + DEBUG_FILE + "]: ipServiceccessKey : " + ipServiceAccessKey);

        //-- 3xx --
        ProxyMode proxyMode = config.proxyMode();
        debug.message("[" + DEBUG_FILE + "]: GeoLocationNode::process().proxyMode : " + proxyMode);
        switch (proxyMode) {
            case DIRECT:
                debug.message("[" + DEBUG_FILE + "]: modeIP is set to MODE_IP_DIRECT");
                modeIP = MODE_IP_DIRECT;
                break;
            case PROXY:
                debug.message("[" + DEBUG_FILE + "]: modeIP is set to MODE_CHECK");
                modeIP = MODE_IP_PROXY;
                break;
            case SHARED_STATE:
                debug.message("[" + DEBUG_FILE + "]: modeIP is set to MODE_SHARED_STATE");
                modeIP = MODE_IP_SHARED_STATE;
                break;
            default:
                debug.message("[" + DEBUG_FILE + "]: modeIP not specified - default MODE_IP_DIRECT is used");
                modeIP = MODE_IP_DIRECT;
                break;
        }
        proxyAttribute = config.proxyAttribute();
        debug.message("[" + DEBUG_FILE + "]: proxyAttribute : " + proxyAttribute);

        //-- 4xx --
        distanceUnit = config.distanceUnit();
        debug.message("[" + DEBUG_FILE + "]: distanceUnit : " + distanceUnit);

        //-- 5xx --
        distanceRisk = config.distanceRisk();
        debug.message("[" + DEBUG_FILE + "]: distanceRisk : " + distanceRisk);
        distanceNoRisk = Double.parseDouble(config.distanceNoRisk());
        debug.message("[" + DEBUG_FILE + "]: distanceNoRisk : " + distanceNoRisk);
        distanceLowRisk = Double.parseDouble(config.distanceLowRisk());
        debug.message("[" + DEBUG_FILE + "]: distanceLowRisk " + distanceLowRisk);
        distanceModerateRisk = Double.parseDouble(config.distanceModerateRisk());
        debug.message("[" + DEBUG_FILE + "]: distanceModerateRisk " + distanceModerateRisk);

        //-- 6xx --
        speedLimitRisk = config.speedLimitRisk();
        debug.message("[" + DEBUG_FILE + "]: speedLimitRisk : " + speedLimitRisk);
        speedLimitNoRisk = Double.parseDouble(config.speedLimitNoRisk());
        debug.message("[" + DEBUG_FILE + "]: speedLimitNoRisk : " + speedLimitNoRisk);
        speedLimitLowRisk = Double.parseDouble(config.speedLimitLowRisk());
        debug.message("[" + DEBUG_FILE + "]: speedLimitLowRisk : " + speedLimitLowRisk);
        speedLimitModerateRisk = Double.parseDouble(config.speedLimitModerateRisk());
        debug.message("[" + DEBUG_FILE + "]: speedLimitModerateRisk : " + speedLimitModerateRisk);

        //-- 7xx --
        countryListType = config.countryListType();
        debug.message("[" + DEBUG_FILE + "]: countryListType : " + countryListType);
        countryWhiteList = config.countryWhiteList();
        debug.message("[" + DEBUG_FILE + "]: countryWhiteList : " + countryWhiteList);
        countryBlackList = config.countryBlackList();
        debug.message("[" + DEBUG_FILE + "]: countryBlackList : " + countryBlackList);

    }

    private String charToString(char[] temporaryPassword) {
        if (temporaryPassword == null) {
            temporaryPassword = new char[0];
        }
        char[] password = new char[temporaryPassword.length];
        System.arraycopy(temporaryPassword, 0, password, 0, temporaryPassword.length);
        return new String(password);
    }

    /**
     * Set the identity object from the username in the config
     *
     * @param context
     */
    private void setIdentity(TreeContext context) {

        if (context.sharedState.get(USERNAME).asString() != null) {
            userIdentity = coreWrapper.getIdentity(context.sharedState.get(USERNAME).asString(), context.sharedState.get(REALM).asString());
        } else {
            //-- User ID <<DEBUG>> --
            userIdentity = coreWrapper.getIdentity("user.0", context.sharedState.get(REALM).asString());
        }
        debug.message("[" + DEBUG_FILE + "]: setIdentity() : " + userIdentity.toString() );
        debug.message("[" + DEBUG_FILE + "]: setIdentity().username : " + userIdentity.getName());

    }

    /**
     * Set the loginIP value to clientIP::timestamp
     * Persist to directory through the userIdentity object
     *
     * @param context
     */
    private void setLoginIP(TreeContext context) {

        //Create payload that will be saved to profile
        Map<String, Set> map = new HashMap<String, Set>();
        Set<String> values = new HashSet<String>();

        String ip;

        try {
            switch (modeIP) {
                case MODE_IP_DIRECT:
                    String testTime = Instant.now().toString();
                    loginIP = parseIP(context.request.clientIp.toString()) + "::" + Instant.now().toString();
                    debug.message("[" + DEBUG_FILE + "]: setLoginIP().IP : " + loginIP);
                    break;
                case MODE_IP_PROXY:
                    if (proxyAttribute.length() > 0) {
                        loginIP = parseIP(context.request.headers.get(proxyAttribute).toString()) + "::" + Instant.now().toString();
                        debug.message("[" + DEBUG_FILE + "]: setLoginIP().IP : " + loginIP);
                    } else {
                        debug.message("[" + DEBUG_FILE + "]: The header name must be specified if node is configured in proxy mode.");
                    }
                    break;
                case MODE_IP_SHARED_STATE:
                    if (proxyAttribute.length() > 0) {
                        loginIP = parseIP(context.sharedState.get(proxyAttribute).asString()) + "::" + Instant.now().toString();
                        debug.message("[" + DEBUG_FILE + "]: setLoginIP().IP : " + loginIP);
                    } else {
                        debug.message("[" + DEBUG_FILE + "]: The shared state attribute name must be specified if node is configured in shared state mode.");
                    }
                    break;
            }

        } catch (Exception e) {
            debug.warning("[" + DEBUG_FILE + "]: The login IP could not be saved to the user object.");
        }

        try {
            values.add(loginIP);
            map.put(ipDataStoreField, values);

            userIdentity.setAttributes(map);
            userIdentity.store();
            debug.message("[" + DEBUG_FILE + "]: MAP : " + map.toString());
        } catch (Exception e) {
            debug.warning("[" + DEBUG_FILE + "]:  The login IP could not be saved to the user object.");
        }

    }

    private void loadLoginIP() {
        try {
            String loadVal = userIdentity.getAttribute(ipDataStoreField).toString();
            if (loadVal.startsWith("["))
                loginIP = loadVal.substring(1,loadVal.length()-1);
            else
                loginIP = loadVal;
            debug.message("[" + DEBUG_FILE + "]: loadLoginIP() : " + loginIP);
        } catch (Exception e) {
            debug.warning("[" + DEBUG_FILE + "]:  The login IP could not be loaded to the user object.");
        }
    }

    /**
     * Add coordinates to the loginIP (IP::timestamp::latitude::longitude)
     */
    private void setLoginIPCoordinates() {

        OutputStream out = null;
        BufferedReader in = null;
        JSONObject result = null;
        Double ipLatitude = null;
        Double ipLongitude = null;
        String ipCountryCode = null;
        String ip;

        //Create payload that will be saved to profile
        Map<String, Set> map = new HashMap<String, Set>();
        Set<String> values = new HashSet<String>();

        switch (loginIP.split("::").length) {
            case 4:
                // IP, timestamp, latitude, longitude have all been set
                debug.message("[" + DEBUG_FILE + "]: "  + loginIP);
                break;
            case 2:
                // IP and timestamp have been set
                debug.message("[" + DEBUG_FILE + "]: "  + loginIP);

                ip = loginIP.split("::")[0];
                debug.message("[" + DEBUG_FILE + "]: ***** " + ip.substring(ip.length()));
                if (ip.substring(ip.length()).equals("]")) ip = ip.substring(1,ip.length()-1);
                try{
                    HttpURLConnection conn = (HttpURLConnection) new URL(buildServiceURL(ip)).openConnection();
                    debug.message ("[" + DEBUG_FILE + "]: " + buildServiceURL(ip));
                    conn.setDoOutput(true);
                    out = conn.getOutputStream();

                    out.write(ip.getBytes());
                    in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

                    StringBuilder response = new StringBuilder();
                    String line = null;
                    while ((line = in.readLine()) != null) {
                        response.append(line);
                    }

                    result = new JSONObject(response.toString());

                    try {
                        switch (provider) {
                            case IPSTACK:
                                ipLongitude = result.getDouble("longitude");
                                debug.message("[" + DEBUG_FILE + "]: " + " longitude " + ipLongitude);
                                ipLatitude = result.getDouble("latitude");
                                debug.message("[" + DEBUG_FILE + "]: " + " latitude " + ipLatitude);
                                ipCountryCode = result.getString("country_code");
                                debug.message("[" + DEBUG_FILE + "]: " + " country code " + ipCountryCode);
                                break;
                            case IPAPI:
                                ipLongitude = result.getDouble("lon");
                                debug.message("[" + DEBUG_FILE + "]: " + " longitude " + ipLongitude);
                                ipLatitude = result.getDouble("lat");
                                debug.message("[" + DEBUG_FILE + "]: " + " latitude " + ipLatitude);
                                ipCountryCode = result.getString("countryCode");
                                debug.message("[" + DEBUG_FILE + "]: " + " country code " + ipCountryCode);
                                break;
                        }

                    } catch (JSONException e) {
                        debug.warning("[" + DEBUG_FILE + "]: " + "ERROR - Location info not available");
                    } catch (Exception e) {
                        debug.warning("[" + DEBUG_FILE + "]: " + "ERROR - Location info not available '{}' ", e);
                    }

                    debug.message("[" + DEBUG_FILE + "]: FULL JSON RETURN : " + result.toString());

                }
                catch(Exception e){
                    debug.error("[" + DEBUG_FILE + "]: " + "ERROR calling REST '{}' ", e);
                }
                finally{
                    if (out != null){
                        try {out.close();} catch (Exception e) {debug.warning("[" + DEBUG_FILE + "]: " + e);}
                    }
                    if (in != null){
                        try {in.close();} catch (Exception e) {debug.warning("[" + DEBUG_FILE + "]: " + e);}
                    }
                }

                try {
                    if (!(ipLatitude.isNaN() && ipLongitude.isNaN())) {
                        loginIP += "::" + ipLatitude + "::" + ipLongitude + "::" + ipCountryCode;
                        values.add(loginIP);
                    }
                    map.put(ipDataStoreField, values);

                    userIdentity.setAttributes(map);
                    userIdentity.store();
                    debug.message("[" + DEBUG_FILE + "]: MAP : " + map.toString());
                } catch (Exception e) {
                    debug.error("[" + DEBUG_FILE + "]:  The login IP could not be saved to the user object.");
                }

                debug.error("[" + DEBUG_FILE + "]: setLoginIPCoordinates.loginIP() : " + loginIP);

                break;
            default:
                // Throw error
                break;
        }
    }

    private void setCurrentIP(TreeContext context)  {
        try {
            switch (modeIP) {
                case MODE_IP_DIRECT:
                    String testTime = Instant.now().toString();
                    currentIP = parseIP(context.request.clientIp.toString()) + "::" + Instant.now().toString();
                    if (currentIP.substring(currentIP.length()).equals("]")) currentIP = currentIP.substring(1,currentIP.length()-1);
                    //-- <<DEBUG>> --
                    //currentIP = "74.104.191.74" + "::" + Instant.now().toString();
                    debug.message("[" + DEBUG_FILE + "]: currentIP().IP : " + currentIP);
                    break;
                case MODE_IP_PROXY:
                    if (proxyAttribute.length() > 0) {
                        currentIP = parseIP(context.request.headers.get(proxyAttribute).toString()) + "::" + Instant.now().toString();
                        debug.message("[" + DEBUG_FILE + "]: currentIP().IP : " + currentIP);
                    } else {
                        debug.error("[" + DEBUG_FILE + "]: The header name must be specified if node is configured in proxy mode.");
                    }
                    break;
                case MODE_IP_SHARED_STATE:
                    if (proxyAttribute.length() > 0) {
                        currentIP = parseIP(context.sharedState.get(proxyAttribute).asString()) + "::" + Instant.now().toString();
                        debug.message("[" + DEBUG_FILE + "]: setCurrentIP().IP : " + currentIP);
                    } else {
                        debug.message("[" + DEBUG_FILE + "]: The shared state attribute name must be specified if node is configured in shared state mode.");
                    }
                    break;
            }

        } catch (Exception e) {
            debug.error("[" + DEBUG_FILE + "]: The current IP could not be saved.");
        }
    }

    /**
     * Add coordinates to the loginIP (IP::timestamp::latitude::longitude)
     */
    private void setCurrentIPCoordinates() {

        OutputStream out = null;
        BufferedReader in = null;
        JSONObject result = null;
        Double ipLatitude = null;
        Double ipLongitude = null;
        String ipCountryCode = null;
        String ip;

        switch (currentIP.split("::").length) {
            case 4:
                // IP, timestamp, latitude, longitude have all been set
                debug.message("[" + DEBUG_FILE + "]: "  + currentIP);
                break;
            case 2:
                // IP and timestamp have been set
                debug.message("[" + DEBUG_FILE + "]: "  + currentIP);

                ip = currentIP.split("::")[0];
                try{
                    HttpURLConnection conn = (HttpURLConnection) new URL(buildServiceURL(ip)).openConnection();
                    debug.message ("[" + DEBUG_FILE + "]: " + buildServiceURL(ip));
                    conn.setDoOutput(true);
                    out = conn.getOutputStream();

                    out.write(ip.getBytes());
                    in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

                    StringBuilder response = new StringBuilder();
                    String line = null;
                    while ((line = in.readLine()) != null) {
                        response.append(line);
                    }

                    result = new JSONObject(response.toString());

                    try {
                        switch (provider) {
                            case IPSTACK:
                                ipLongitude = result.getDouble("longitude");
                                debug.message("[" + DEBUG_FILE + "]: " + " longitude " + ipLongitude);
                                ipLatitude = result.getDouble("latitude");
                                debug.message("[" + DEBUG_FILE + "]: " + " latitude " + ipLatitude);
                                ipCountryCode = result.getString("country_code");
                                debug.message("[" + DEBUG_FILE + "]: " + " country code " + ipCountryCode);
                                break;
                            case IPAPI:
                                ipLongitude = result.getDouble("lon");
                                debug.message("[" + DEBUG_FILE + "]: " + " longitude " + ipLongitude);
                                ipLatitude = result.getDouble("lat");
                                debug.message("[" + DEBUG_FILE + "]: " + " latitude " + ipLatitude);
                                ipCountryCode = result.getString("countryCode");
                                debug.message("[" + DEBUG_FILE + "]: " + " country code " + ipCountryCode);
                                break;
                        }

                    } catch (JSONException e) {
                        debug.error("[" + DEBUG_FILE + "]: " + "ERROR - Location info not available");
                    } catch (Exception e) {
                        debug.error("[" + DEBUG_FILE + "]: " + "ERROR - Location info not available '{}' ", e);
                    }

                    debug.message("[" + DEBUG_FILE + "]: FULL CURRENT JSON RETURN : " + result.toString());

                }
                catch(Exception e){
                    debug.error("[" + DEBUG_FILE + "]: " + "ERROR calling REST '{}' ", e);
                }
                finally{
                    if (out != null){
                        try {out.close();} catch (Exception e) {debug.error("[" + DEBUG_FILE + "]: " + e);}
                    }
                    if (in != null){
                        try {in.close();} catch (Exception e) {debug.error("[" + DEBUG_FILE + "]: " + e);}
                    }
                }

                try {
                    if (!(ipLatitude.isNaN() && ipLongitude.isNaN())) {
                        currentIP += "::" + ipLatitude + "::" + ipLongitude + "::" + ipCountryCode;
                    }
                } catch (Exception e) {
                    debug.error("[" + DEBUG_FILE + "]:  The login IP could not be saved to the user object.");
                }

                debug.message("[" + DEBUG_FILE + "]: setCurrentIPCoordinates.currentIP() : " + currentIP);

                break;
            default:
                // Throw error ?
                break;
        }
    }

    private void setDistanceFromLogin() {

        Double loginLongitude = Double.valueOf(loginIP.split("::")[3]);
        Double loginLatitude = Double.valueOf(loginIP.split("::")[2]);
        Double currentLongitude= Double.valueOf(currentIP.split("::")[3]);
        Double currentLatitude = Double.valueOf(currentIP.split("::")[2]);;
        Instant loginTime = Instant.parse(loginIP.split("::")[1]);
        Instant currentTime = Instant.parse(currentIP.split("::")[1]);
        Duration duration = Duration.between(loginTime,currentTime);
        Double hoursSinceLogin = duration.getSeconds()/3600.0;

        double earthRadius = 6371000; //meters
        double dLat = Math.toRadians(currentLatitude-loginLatitude);
        double dLng = Math.toRadians(currentLongitude-loginLongitude);
        double a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                Math.cos(Math.toRadians(loginLatitude)) * Math.cos(Math.toRadians(currentLatitude)) *
                        Math.sin(dLng/2) * Math.sin(dLng/2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        distanceKilometers = (long)((earthRadius * c)/1000);
        distanceMiles = (long) (distanceKilometers / 1.6);

        milesPerHour = distanceMiles/hoursSinceLogin;
        kmPerHour = distanceKilometers/hoursSinceLogin;

        debug.warning("[" + DEBUG_FILE + "]: DISTANCE IN MILES : " + distanceMiles);
        debug.warning("[" + DEBUG_FILE + "]: DISTANCE IN KM : " + distanceKilometers);

        debug.warning("[" + DEBUG_FILE + "]: HOURS SINCE LAST LOGIN : " + hoursSinceLogin);
        debug.warning("[" + DEBUG_FILE + "]: SPEED IN MILES : " + milesPerHour);
        debug.warning("[" + DEBUG_FILE + "]: SPEED IN KM : " + kmPerHour);

        return;
    }

    public String parseIP (String ip) {
        if (ip.substring(0,1).equals("[")) {
            return ip.substring(1,ip.length()-1);
        } else {
            return ip;
        }
    }

    /**
     * Builds the service URL for supported providers
     *
     * @param ip
     * @return
     */
    private String buildServiceURL(String ip) {
        switch (provider) {
            case IPAPI:
                ipServiceURL = "http://ip-api.com/json/" + ip;
                break;
            case IPSTACK:
                ipServiceURL = "http://api.ipstack.com/" + ip + "?access_key=" + ipServiceAccessKey;
                break;
        }
        debug.message("[" + DEBUG_FILE + "]: Service URL : " + ip + " :: " + ipServiceURL);
        return ipServiceURL;
    }

    private boolean checkLoginCountryOnWhiteList() {
        String loginCountry = null;
        if (loginIP.split("::").length > 4) {
            loginCountry = loginIP.split("::")[4];
            if (countryWhiteList.contains(loginCountry)) {
                debug.message("[" + DEBUG_FILE + "]: Login county (" + loginCountry + ") is in white list");
                return true;
            }
        }
        return false;
    }

    private boolean checkLoginCountryOnBlackList() {
        String loginCountry = null;
        if (loginIP.split("::").length > 4) {
            loginCountry = loginIP.split("::")[4];
            if (countryBlackList.contains(loginCountry)) {
                debug.message("[" + DEBUG_FILE + "]: Login county (" + loginCountry + ") is on black list");
                return true;
            }
        }
        return false;
    }

    private boolean checkCurrentCountryOnWhiteList() {
        String currentCountry = null;
        if (currentIP.split("::").length > 4) {
            currentCountry = currentIP.split("::")[4];
            if (countryWhiteList.contains(currentCountry)) {
                debug.message("[" + DEBUG_FILE + "]: Current county (" + currentCountry + ") is in white list");
                return true;
            }
        }
        return false;
    }

    private boolean checkCurrentCountryOnBlackList() {
        String currentCountry = null;
        if (currentIP.split("::").length > 4) {
            currentCountry = currentIP.split("::")[4];
            if (countryBlackList.contains(currentCountry)) {
                debug.message("[" + DEBUG_FILE + "]: Current county (" + currentCountry + ") is on black list");
                return true;
            }
        }
        return false;
    }

    /**
     * The possible outcomes for the GeoLocationNode - Risk Levels
     */
    public enum GeoLocationOutcome {
        NONE,
        LOW,
        MODERATE,
        HIGH,
        UNKNOWN
    }

    public enum NodeMode {
        CHECK,
        STORE
    }

    public enum Provider {
        IPAPI,
        IPSTACK
    }

    public enum ProxyMode {
        DIRECT,
        PROXY,
        SHARED_STATE
    }

    public enum DistanceUnit {
        MILE,
        KM
    }

    public enum CountryListType {
        NONE,
        WHITE,
        BLACK
    }

    /**
     * Defines the possible outcomes from this GeoLocation node.
     */
    public static class GeoLocationOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(GeoLocationNode.BUNDLE,
                    GeoLocationNode.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(GeoLocationOutcome.NONE.name(), bundle.getString("noRiskOutcome")),
                    new Outcome(GeoLocationOutcome.LOW.name(), bundle.getString("lowRiskOutcome")),
                    new Outcome(GeoLocationOutcome.MODERATE.name(), bundle.getString("moderateRiskOutcome")),
                    new Outcome(GeoLocationOutcome.HIGH.name(), bundle.getString("highRiskOutcome")),
                    new Outcome(GeoLocationOutcome.UNKNOWN.name(), bundle.getString("unknownRiskOutcome"))
            );
        }
    }

}