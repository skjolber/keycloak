/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.testsuite.saml;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.apache.xerces.util.XMLCatalogResolver;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.DerUtils;
import org.keycloak.common.util.StreamUtil;
import org.keycloak.dom.saml.v2.metadata.KeyTypes;
import org.keycloak.keys.RsaKeyMetadata;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.SamlService;
import org.keycloak.saml.SPMetadataDescriptor;
import org.keycloak.saml.processing.core.util.IDFedLSInputResolver;
import org.keycloak.services.resources.RealmsResource;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ValidationTest {

    private static final String PRIVATE_KEY = "MIICWwIBAAKBgQDVG8a7xGN6ZIkDbeecySygcDfsypjUMNPE4QJjis8B316CvsZQ0hcTTLUyiRpHlHZys2k3xEhHBHymFC1AONcvzZzpb40tAhLHO1qtAnut00khjAdjR3muLVdGkM/zMC7G5s9iIwBVhwOQhy+VsGnCH91EzkjZ4SVEr55KJoyQJQIDAQABAoGADaTtoG/+foOZUiLjRWKL/OmyavK9vjgyFtThNkZY4qHOh0h3og0RdSbgIxAsIpEa1FUwU2W5yvI6mNeJ3ibFgCgcxqPk6GkAC7DWfQfdQ8cS+dCuaFTs8ObIQEvU50YzeNPiiFxRA+MnauCUXaKm/PnDfjd4tPgru7XZvlGh0wECQQDsBbN2cKkBKpr/b5oJiBcBaSZtWiMNuYBDn9x8uORj+Gy/49BUIMHF2EWyxOWz6ocP5YiynNRkPe21Zus7PEr1AkEA5yWQOkxUTIg43s4pxNSeHtL+Ebqcg54lY2xOQK0yufxUVZI8ODctAKmVBMiCKpU3mZQquOaQicuGtocpgxlScQI/YM31zZ5nsxLGf/5GL6KhzPJT0IYn2nk7IoFu7bjn9BjwgcPurpLA52TNMYWQsTqAKwT6DEhG1NaRqNWNpb4VAkBehObAYBwMm5udyHIeEc+CzUalm0iLLa0eRdiN7AUVNpCJ2V2Uo0NcxPux1AgeP5xXydXafDXYkwhINWcNO9qRAkEA58ckAC5loUGwU5dLaugsGH/a2Q8Ac8bmPglwfCstYDpl8Gp/eimb1eKyvDEELOhyImAv4/uZV9wN85V0xZXWsw==";

    /**
     * The public certificate that corresponds to {@link #PRIVATE_KEY}.
     */
    private static final String PUBLIC_CERT = "MIIDdzCCAl+gAwIBAgIEbySuqTANBgkqhkiG9w0BAQsFADBsMRAwDgYDVQQGEwdVbmtub3duMRAwDgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRAwDgYDVQQKEwdVbmtub3duMRAwDgYDVQQLEwdVbmtub3duMRAwDgYDVQQDEwdVbmtub3duMB4XDTE1MDEyODIyMTYyMFoXDTE3MTAyNDIyMTYyMFowbDEQMA4GA1UEBhMHVW5rbm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5rbm93bjEQMA4GA1UEChMHVW5rbm93bjEQMA4GA1UECxMHVW5rbm93bjEQMA4GA1UEAxMHVW5rbm93bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAII/K9NNvXi9IySl7+l2zY/kKrGTtuR4WdCI0xLW/Jn4dLY7v1/HOnV4CC4ecFOzhdNFPtJkmEhP/q62CpmOYOKApXk3tfmm2rwEz9bWprVxgFGKnbrWlz61Z/cjLAlhD3IUj2ZRBquYgSXQPsYfXo1JmSWF5pZ9uh1FVqu9f4wvRqY20ZhUN+39F+1iaBsoqsrbXypCn1HgZkW1/9D9GZug1c3vB4wg1TwZZWRNGtxwoEhdK6dPrNcZ+6PdanVilWrbQFbBjY4wz8/7IMBzssoQ7Usmo8F1Piv0FGfaVeJqBrcAvbiBMpk8pT+27u6p8VyIX6LhGvnxIwM07NByeSUCAwEAAaMhMB8wHQYDVR0OBBYEFFlcNuTYwI9W0tQ224K1gFJlMam0MA0GCSqGSIb3DQEBCwUAA4IBAQB5snl1KWOJALtAjLqD0mLPg1iElmZP82Lq1htLBt3XagwzU9CaeVeCQ7lTp+DXWzPa9nCLhsC3QyrV3/+oqNli8C6NpeqI8FqN2yQW/QMWN1m5jWDbmrWwtQzRUn/rh5KEb5m3zPB+tOC6e/2bV3QeQebxeW7lVMD0tSCviUg1MQf1l2gzuXQo60411YwqrXwk6GMkDOhFDQKDlMchO3oRbQkGbcP8UeiKAXjMeHfzbiBr+cWz8NYZEtxUEDYDjTpKrYCSMJBXpmgVJCZ00BswbksxJwaGqGMPpUKmCV671pf3m8nq3xyiHMDGuGwtbU+GE8kVx85menmp8+964nin";
        
    private IDFedLSInputResolver idFedLSInputResolver = new IDFedLSInputResolver();
    
    public static String getIDPMetadataDescriptor() throws IOException {
        InputStream is = SamlService.class.getResourceAsStream("/idp-metadata-template.xml");
        String template = StreamUtil.readString(is);
        template = template.replace("${idp.entityID}", "http://keycloak.org/auth/realms/test");
        template = template.replace("${idp.sso.HTTP-POST}", "http://keycloak.org/auth/realms/test/saml");
        template = template.replace("${idp.sso.HTTP-Redirect}", "http://keycloak.org/auth/realms/test/saml");
        template = template.replace("${idp.sls.HTTP-POST}", "http://keycloak.org/auth/realms/test/saml");
        template = template.replace("${idp.signing.certificates}", KeycloakModelUtils.generateKeyPairCertificate("test").getCertificate());
        return template;
    }

    private void validate(Source xmlFile) throws SAXException {
        // make sure there is no outgoing call to get schema online
        URL schemaFile = getClass().getResource("/schema/saml/v2/saml-schema-metadata-2.0.xsd");
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        
        XMLCatalogResolver resolver = new XMLCatalogResolver();
        resolver.setPreferPublic(true);
        resolver.setCatalogList(new String[] { "src/test/resources/saml/xml-schema-validation/catalog.xml" });
        schemaFactory.setResourceResolver(new LSResourceResolver() {
            
            @Override
            public LSInput resolveResource(String type, String namespaceURI, String publicId, String systemId, String baseURI) {
                
                LSInput input = resolver.resolveResource(type, namespaceURI, publicId, systemId, baseURI);
                if(input == null) {
                    input = idFedLSInputResolver.resolveResource(type, namespaceURI, publicId, systemId, baseURI);
                }
                if(input == null) {
                    throw new IllegalArgumentException("Unable to resolve " + systemId);
                }
                return input;
            }
        });
        
        Schema schema = schemaFactory.newSchema(schemaFile);
        Validator validator = schema.newValidator();
        try {
            validator.validate(xmlFile);
            System.out.println(xmlFile.getSystemId() + " is valid");
        } catch (Exception e) {
            System.out.println(xmlFile.getSystemId() + " is NOT valid");
            System.out.println("Reason: " + e.getLocalizedMessage());
            Assert.fail();
        }
    }
    
    @Test
    public void testIDPDescriptor() throws Exception {
        
        UriInfo uriInfo = mock(UriInfo.class);
        UriBuilder value = mock(UriBuilder.class);
        when(value.build("test")).thenReturn(new URI("http://keycloak.org/auth/realms/test"));
        when(value.path(any(Class.class))).thenReturn(value);
        when(value.path(RealmsResource.class, "getRealmResource")).thenReturn(value);
        when(value.path(RealmsResource.class, "getProtocol")).thenReturn(value);
        
        when(value.build(any())).thenReturn(new URI("http://keycloak.org/auth/realms/test"));
        when(uriInfo.getBaseUriBuilder()).thenReturn(value);
        
        KeyManager keyManager = mock(KeyManager.class);
        List<RsaKeyMetadata> list = new ArrayList<>();
        RsaKeyMetadata key = new RsaKeyMetadata();
        X509Certificate decodeCertificate = DerUtils.decodeCertificate(new ByteArrayInputStream(Base64.decode(PUBLIC_CERT)));

        key.setCertificate(decodeCertificate);
        key.setPublicKey(decodeCertificate.getPublicKey());
        list.add(key);

        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test");

        when(keyManager.getRsaKeys(realm, false)).thenReturn(list);
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.keys()).thenReturn(keyManager);
        
        String content = SamlService.getIDPMetadataDescriptor(uriInfo, session, realm);
        Source xmlFile = new StreamSource(new ByteArrayInputStream(content.getBytes()), "IDPSSODescriptor");
        validate(xmlFile);
    }
    
    @Test
    public void testBrokerExportDescriptor() throws Exception {
        String spCertificate = SPMetadataDescriptor.xmlKeyInfo("        ", null, PUBLIC_CERT, KeyTypes.SIGNING.value(), true);
        
        String str = SPMetadataDescriptor.getSPDescriptor(
                "POST", "http://realm/assertion", "http://realm/logout", true, false, "test", SamlProtocol.SAML_DEFAULT_NAMEID_FORMAT, spCertificate
        );
        Source xmlFile = new StreamSource(new ByteArrayInputStream(str.getBytes()), "IDPSSODescriptor");
        validate(xmlFile);
        
    }
}
