<%@ page errorPage="error.jsp"%>
<%@ page import="org.jivesoftware.openfire.net.SSLConfig"%>
<%@ page import="org.jivesoftware.util.ParamUtils"%>
<%@ page import="java.security.cert.X509Certificate"%>
<%@ page import="java.util.HashMap"%>
<%@ page import="java.util.Map"%>
<%@ page import="org.jivesoftware.openfire.keystore.Purpose" %>
<%@ page import="org.jivesoftware.openfire.keystore.TrustStoreConfig" %>
<%@ page import="java.util.Set" %>
<%@ taglib uri="admin" prefix="admin" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>

<jsp:useBean id="webManager" class="org.jivesoftware.util.WebManager" />
<jsp:useBean id="now" class="java.util.Date"/>
<%  webManager.init(request, response, session, application, out );

    final boolean delete          = ParamUtils.getBooleanParameter( request, "delete" );
    final String alias            = ParamUtils.getParameter( request, "alias" );

    final String storePurposeText = ParamUtils.getParameter(request, "storePurpose");

    final Map<String, String> errors = new HashMap<>();

    Purpose storePurpose = null;
    TrustStoreConfig storeConfig = null;
    try
    {
        storePurpose = Purpose.valueOf( storePurposeText );

        if ( !storePurpose.isTrustStore() )
        {
            errors.put( "storePurpose", "should be a trust store (not an identity store)");
        }
        else
        {
            storeConfig = (TrustStoreConfig) SSLConfig.getInstance().getStoreConfig( storePurpose );
            if ( storeConfig == null )
            {
                errors.put( "storeConfig", "Unable to get an instance." );
            }
        }
    }
    catch (RuntimeException ex)
    {
        errors.put( "storePurpose", ex.getMessage() );
    }

    if ( errors.isEmpty() )
    {
        pageContext.setAttribute( "storePurpose", storePurpose );
        pageContext.setAttribute( "storeConfig", storeConfig );

        final Set<Purpose> sameStorePurposes = SSLConfig.getInstance().getOtherPurposesForSameStore( storePurpose );
        pageContext.setAttribute( "sameStorePurposes", sameStorePurposes );

        if ( delete )
        {
            if ( alias == null )
            {
                errors.put( "alias", "The alias has not been specified." );
            }
            else
            {
                try
                {
                    storeConfig.delete( alias );

                    // Log the event
                    webManager.logEvent( "deleted SSL cert from " + storePurposeText + " with alias " + alias, null );
                    response.sendRedirect( "security-truststore.jsp?storePurpose=" + storePurposeText + "&deletesuccess=true" );
                    return;
                }
                catch ( Exception e )
                {
                    errors.put( "delete", e.getMessage() );
                }
            }
        }
    }

    pageContext.setAttribute( "errors", errors );
%>

<html>
    <head>
        <title><fmt:message key="certificate-management.purpose.${storePurpose}.title"/></title>
        <meta name="pageID" content="security-truststore"/>
        <style>
            .info-header {
                background-color: #eee;
                font-size: 10pt;
            }
            .info-table {
                margin-right: 12px;
            }
            .info-table .c1 {
                text-align: right;
                vertical-align: top;
                color: #666;
                font-weight: bold;
                font-size: 9pt;
                white-space: nowrap;
            }
            .info-table .c2 {
                font-size: 9pt;
                width: 90%;
            }
        </style>
    </head>
    <body>
        <c:forEach var="err" items="${errors}">
            <admin:infobox type="error">
                <c:choose>
                    <c:when test="${err.key eq 'type'}">
                        <c:out value="${err.key}"/>
                        <c:if test="${not empty err.value}">
                            : <c:out value="${err.value}"/>
                        </c:if>
                    </c:when>

                    <c:otherwise>
                        <c:out value="${err.key}"/>
                        <c:if test="${not empty err.value}">
                            : <c:out value="${err.value}"/>
                        </c:if>
                    </c:otherwise>
                </c:choose>
            </admin:infobox>
        </c:forEach>

        <c:if test="${param.deletesuccess}">
            <admin:infobox type="success"><fmt:message key="ssl.certificates.deleted"/></admin:infobox>
        </c:if>
        <c:if test="${param.importsuccess}">
            <admin:infobox type="success"><fmt:message key="ssl.certificates.added_updated"/></admin:infobox>
        </c:if>

        <c:if test="${storePurpose != null}">
            <p>
                <fmt:message key="certificate-management.purpose.${storePurpose}.description"/>
            </p>

            <table border="0" width="100%">
                <td valign="top" width="60%">
                    <table cellpadding="2" cellspacing="2" border="0" class="info-table">
                        <thead>
                        <tr><th colspan="2" class="info-header">Store Configuration</th></tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td class="c1">File location:</td>
                            <td class="c2"><c:out value="${storeConfig.path}"/></td>
                        </tr>
                        <tr>
                            <td class="c1">Type:</td>
                            <td class="c2"><c:out value="${storeConfig.type}"/></td>
                        </tr>
                        <tr>
                            <td class="c1">Password:</td>
                            <td class="c2"><c:out value="${storeConfig.password}"/></td>
                        </tr>
                        </tbody>
                    </table>
                </td>
                <td valign="top" width="40%">
                    <c:if test="${not empty sameStorePurposes}">
                        <admin:infobox type="info">
                            This store is re-used for these additional purposes. Any changes to this store will also affect that functionality!
                            <ul style="margin-top: 1em;">
                                <c:forEach var="sameStorePurpose" items="${sameStorePurposes}">
                                    <li><fmt:message key="certificate-management.purpose.${sameStorePurpose}.title"/></li>
                                </c:forEach>
                            </ul>
                        </admin:infobox>
                    </c:if>
                </td>
            </table>


            <p>
                <fmt:message key="ssl.certificates.truststore.link-to-import">
                    <fmt:param value="<a href='import-truststore-certificate.jsp?storePurpose=${storePurpose}'>"/>
                    <fmt:param value="</a>"/>
                </fmt:message>
            </p>

            <table class="jive-table" cellpadding="0" cellspacing="0" border="0" width="100%">
                <thead>
                    <tr>
                        <th>
                            <fmt:message key="ssl.signing-request.organization"/> <small>(<fmt:message key="ssl.certificates.alias"/>)</small>
                        </th>
                        <th width="20%">
                            <fmt:message key="ssl.certificates.valid-between"/>
                        </th>
                        <th>
                            <fmt:message key="ssl.certificates.algorithm"/>
                        </th>
                        <th width="1%">
                            <fmt:message key="global.delete"/>
                        </th>
                    </tr>
                </thead>

                <tbody>
                    <c:choose>
                        <c:when test="${empty storeConfig.allCertificates}">
                            <tr valign="top">
                                <td colspan="5"><em>(<fmt:message key="global.none"/>)</em></td>
                            </tr>
                        </c:when>
                        <c:otherwise>
                            <c:forEach var="certificateEntry" items="${storeConfig.allCertificates}">
                                <c:set var="certificate" value="${certificateEntry.value}"/>
                                <c:set var="alias" value="${certificateEntry.key}"/>

                                <c:set var="organization" value=""/>
                                <c:set var="commonname" value=""/>
                                <c:forEach var="subjectPart" items="${admin:split(certificate.subjectX500Principal.name, '(?<!\\\\\\\\),')}">
                                    <c:set var="keyValue" value="${fn:split(subjectPart, '=')}"/>
                                    <c:set var="key" value="${fn:toUpperCase(keyValue[0])}"/>
                                    <c:set var="value" value="${admin:replaceAll(keyValue[1], '\\\\\\\\(.)', '$1')}"/>
                                    <c:choose>
                                        <c:when test="${key eq 'O'}">
                                            <c:set var="organization" value="${organization} ${value}"/>
                                        </c:when>
                                        <c:when test="${key eq 'CN'}">
                                            <c:set var="commonname" value="${value}"/>
                                        </c:when>
                                    </c:choose>
                                </c:forEach>

                                <tr valign="top">
                                    <td>
                                        <a href="security-certificate-details.jsp?storePurpose=${storePurpose}&alias=${alias}" title="<fmt:message key='session.row.cliked'/>">
                                            <c:choose>
                                                <c:when test="${empty fn:trim(organization)}">
                                                    <c:out value="${commonname}"/>
                                                </c:when>
                                                <c:otherwise>
                                                    <c:out value="${organization}"/>
                                                </c:otherwise>
                                            </c:choose>
                                        </a>
                                        <small>(<c:out value="${alias}"/>)</small>
                                    </td>
                                    <td>
                                        <c:choose>
                                            <c:when test="${certificate.notAfter lt now or certificate.notBefore gt now}">
                                        <span style="color: red;">
                                            <fmt:formatDate type="DATE" dateStyle="MEDIUM" value="${certificate.notBefore}"/>
                                            -
                                            <fmt:formatDate type="DATE" dateStyle="MEDIUM" value="${certificate.notAfter}"/>
                                        </span>
                                            </c:when>
                                            <c:otherwise>
                                        <span>
                                            <fmt:formatDate type="DATE" dateStyle="MEDIUM" value="${certificate.notBefore}"/>
                                            -
                                            <fmt:formatDate type="DATE" dateStyle="MEDIUM" value="${certificate.notAfter}"/>
                                        </span>
                                            </c:otherwise>
                                        </c:choose>
                                    </td>
                                    <td width="2%">
                                        <c:out value="${certificate.publicKey.algorithm}"/>
                                    </td>
                                    <td width="1" align="center">
                                        <a href="security-truststore.jsp?storePurpose=${storePurpose}&alias=${alias}&delete=true"
                                           title="<fmt:message key="global.click_delete"/>"
                                           onclick="return confirm('<fmt:message key="ssl.certificates.confirm_delete"/>');"
                                                ><img src="images/delete-16x16.gif" width="16" height="16" border="0" alt=""></a>
                                    </td>
                                </tr>
                            </c:forEach>
                        </c:otherwise>
                    </c:choose>
                </tbody>
            </table>
        </c:if>
    </body>
</html>
