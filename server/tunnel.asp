<%@ Language=VBScript %>
<%
Option Explicit
Response.Buffer = False
Response.ContentType = "application/json"
Response.AddHeader "Cache-Control", "no-store"

' Classic ASP/VBScript has no standard raw TCP socket API. Unlike ASP.NET and
' Java, IIS classic ASP cannot implement the run action without a non-standard
' COM/ActiveX socket component. This endpoint therefore fails closed instead of
' shelling out to another process or depending on an unsafe/unportable COM object.

If UCase(Request.ServerVariables("REQUEST_METHOD")) <> "POST" Then
    Response.AddHeader "Allow", "POST"
    Response.Status = "405 Method Not Allowed"
    Response.Write "{""error"":""method_not_allowed""}"
    Response.End
End If

Dim isHttps, forwardedProto
isHttps = False
If LCase(Request.ServerVariables("HTTPS")) = "on" Then
    isHttps = True
End If

' Keep this False unless X-Forwarded-Proto can only be supplied by a trusted
' reverse proxy. Set to True only in that deployment model.
Const TRUST_FORWARDED_PROTO = False
If (Not isHttps) And TRUST_FORWARDED_PROTO Then
    forwardedProto = LCase(Trim(Split(Request.ServerVariables("HTTP_X_FORWARDED_PROTO"), ",")(0)))
    If forwardedProto = "https" Then isHttps = True
End If

If Not isHttps Then
    Response.Status = "400 Bad Request"
    Response.Write "{""error"":""https_required""}"
    Response.End
End If

Response.Status = "501 Not Implemented"
Response.Write "{""error"":""classic_asp_raw_tcp_not_supported"",""use"":""tunnel.ashx or tunnel.aspx on IIS""}"
Response.End
%>
