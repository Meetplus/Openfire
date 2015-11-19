<%@ page errorPage="error.jsp"%>
<%@ page import="org.jivesoftware.util.ParamUtils"%>
<%@ page import="org.jivesoftware.openfire.net.SSLConfig"%>
<%@ page import="java.util.HashMap"%>
<%@ page import="java.util.Map"%>
<%@ page import="org.jivesoftware.openfire.keystore.Purpose" %>
<%@ page import="org.jivesoftware.openfire.keystore.TrustStoreConfig" %>

<%@ taglib uri="admin" prefix="admin" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>

<jsp:useBean id="webManager" class="org.jivesoftware.util.WebManager"/>
<%  webManager.init(request, response, session, application, out ); %>

<%  final boolean save             = ParamUtils.getParameter(request, "save") != null;
    final String alias             = ParamUtils.getParameter(request, "alias");
    final String certificate       = ParamUtils.getParameter(request, "certificate");
    final String storePurposeText = ParamUtils.getParameter(request, "storePurpose");

    final Map<String, String> errors = new HashMap<String, String>();

    Purpose storePurpose;
    try
    {
        storePurpose = Purpose.valueOf( storePurposeText );
    } catch (RuntimeException ex) {
        errors.put( "storePurpose", ex.getMessage() );
        storePurpose = null;
    }

    if (! storePurpose.isTrustStore() ) {
        errors.put( "storePurpose", "shoud be a trust store (not an identity store)");
        storePurpose = null;
    }

    pageContext.setAttribute( "storePurpose", storePurpose );

    if (save && errors.isEmpty())
    {
        final TrustStoreConfig trustStoreConfig = (TrustStoreConfig) SSLConfig.getInstance().getStoreConfig( storePurpose );

        if (alias == null || "".equals(alias))
        {
            errors.put("missingalias", "missingalias");
        }
        else if (trustStoreConfig.getStore().containsAlias( alias ))
        {
            // Verify that the provided alias is not already available
            errors.put("existingalias", "existingalias");
        }
        if (certificate == null || "".equals(certificate))
        {
            errors.put("certificate", "certificate-missing");
        }

        if (errors.isEmpty())
        {
            try
            {
                // Import certificate
                trustStoreConfig.installCertificate( alias, certificate );

                // Log the event
                webManager.logEvent("imported SSL certificate in "+ storePurposeText, "alias = "+alias);

                response.sendRedirect( "security-truststore.jsp?storePurpose=" + storePurposeText + "&importsuccess=true" );
                return;
            }
            catch (Throwable e)
            {
                e.printStackTrace();
                errors.put("import", e.getMessage());
            }
        }
    }
%>

<html>
<head>
    <title>
        <fmt:message key="ssl.import.certificate.keystore.${connectivityType}.title"/> - <fmt:message key="ssl.certificates.truststore.${param.type}-title"/>
    </title>
    <meta name="pageID" content="security-truststore-${connectivityType}-${param.type}"/>
</head>
<body>

<% pageContext.setAttribute("errors", errors); %>
<c:forEach var="err" items="${errors}">
    <admin:infobox type="error">
        <c:choose>
            <c:when test="${err.key eq 'type'}">
                <fmt:message key="ssl.import.certificate.keystore.error.type"/>
            </c:when>

            <c:when test="${err.key eq 'missingalias'}">
                <fmt:message key="ssl.import.certificate.keystore.error.alias-missing"/>
            </c:when>

            <c:when test="${err.key eq 'existingalias'}">
                <fmt:message key="ssl.import.certificate.keystore.error.alias-exists"/>
            </c:when>

            <c:when test="${err.key eq 'certificate'}">
                <fmt:message key="ssl.import.certificate.keystore.error.certificate"/>
            </c:when>

            <c:when test="${err.key eq 'import'}">
                <fmt:message key="ssl.import.certificate.keystore.error.import"/>
                <c:if test="${not empty err.value}">
                    <fmt:message key="admin.error"/>: <c:out value="${err.value}"/>
                </c:if>
            </c:when>

            <c:otherwise>
                <c:if test="${not empty err.value}">
                    <fmt:message key="admin.error"/>: <c:out value="${err.value}"/>
                </c:if>
                (<c:out value="${err.key}"/>)
            </c:otherwise>
        </c:choose>
    </admin:infobox>
</c:forEach>

<c:if test="${not empty param.type}">
    <p>
        <fmt:message key="ssl.import.certificate.keystore.${param.type}-intro"/>
    </p>

    <!-- BEGIN 'Import Certificate' -->
    <form action="import-truststore-certificate.jsp?type=${param.type}" method="post" name="f">
        <input type="hidden" name="connectivityType" value="${connectivityType}"/>
        <div class="jive-contentBoxHeader">
            <fmt:message key="ssl.import.certificate.keystore.boxtitle"/>
        </div>
        <div class="jive-contentBox">
            <table cellpadding="3" cellspacing="0" border="0">
                <tbody>
                    <tr valign="top">
                        <td width="1%" nowrap class="c1">
                            <label for="alias"><fmt:message key="ssl.signing-request.alias"/></label>
                        </td>
                        <td width="99%">
                            <input type="text" size="30" maxlength="100" name="alias" id="alias" value="${param.alias}">
                        </td>
                    </tr>
                    <tr valign="top">
                        <td width="1%" nowrap class="c1">
                            <label for="certificate"><fmt:message key="ssl.import.certificate.keystore.certificate"/></label>
                        </td>
                        <td width="99%">
                            <textarea name="certificate" id="certificate" cols="80" rows="20" wrap="virtual">${param.certificate}</textarea>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
        <input type="submit" name="save" value="<fmt:message key="global.save"/>">
    </form>
    <!-- END 'Import Certificate' -->
</c:if>

</body>
</html>
