// ==UserScript==
// @name      SAML Programmatic Access
// @namespace https://signin.aws.amazon.com
// @iconUrl   https://signin.aws.amazon.com/favicon.ico
// @version   1.1
// @author    fendallt@amazon.com
// @match     https://signin.aws.amazon.com/saml
// @grant     GM_getResourceText
// @grant     GM_addStyle
// @require   https://sdk.amazonaws.com/js/aws-sdk-2.678.0.min.js
// @require   https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js
// @require   https://ajax.googleapis.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js
// @resource  JQUI-CSS https://ajax.googleapis.com/ajax/libs/jqueryui/1.12.1/themes/smoothness/jquery-ui.css
// ==/UserScript==

/**
 * This userscript augments the functionality of https://signin.aws.amazon.com/saml
 * to allow the user to retrieve temporary AWS access keys for their assigned roles
 *
 * Note: This script is not responsible for validating the provided SAML token at all.
 * Token validation is done by AWS on the https://signin.aws.amazon.com/saml page and then
 * again by the STS.assumeRoleWithSAML API.
 */
(function() {
  'use strict';
  const STS = new AWS.STS();


  /**
   * The SESSION_DURATION_OVERRIDES property can be used to override the 
   * session duration of access keys for a specific IAM Role.  To specify a 
   * session duration, put the role ARN as the key and desired duration 
   * (in seconds) as the value.
   *
   * Each IAM Role has a defined MaxSessionDuration (between 15 minutes and 
   * 12 hours). The requested duration cannot exceed the allowed duration set 
   * on the role. If you see the message "The requested DurationSeconds exceeds
   * the MaxSessionDuration set for this role", then this is why.
   */
  const SESSION_DURATION_OVERRIDES = {
    'arn:aws:iam::123456789012:role/RoleName': 14400, // Example: 4 hours
  };


  $('#signin_button').text('Console Access');
  // Inject Button for Programmatic Access
  const btn = $('<a id="accesskeys_button">Programmatic Access</a>')
    .attr({ class: 'css3button', href: '#', alt: 'Access Keys', value: 'Access Keys' });
  btn.click(getCredentials);
  $('#input_signin_button').append(btn);


  /**
   * Read the Selected Role and SAML Token from the form, then 
   * call sts.assumeRoleWithSAML to get temporarry AWS Access Keys
   *
   * TODO: The below code could take a second or two to execute,
   * consider showing some kind of spinner during this time
   */
  function getCredentials() {
    const encodedSAML = $('input[name="SAMLResponse"]').val();
    const role = $('input[name="roleIndex"]:checked').val();
    if(!role) return; // Nothing was selected

    // Parse SAML token into an XML DOM we can use
    const rawSAML = atob(encodedSAML);
    const parsedSAML = $.parseXML(rawSAML);
    const $saml = $(parsedSAML);

    const idp = getIDPForRole($saml, role);
    const duration = getSessionDurationForRole($saml, role);

    // Request temporary access keys from AWS STS
    return STS.assumeRoleWithSAML({
      PrincipalArn: idp,
      RoleArn: role,
      SAMLAssertion: encodedSAML, /* SAML Token Base64 encoded */
      DurationSeconds: duration
    }).promise()
      .then((data)=> {
        const accountId = role.substr(13, 12);
        const roleName = role.substr(role.lastIndexOf('/')+1);

        // Render popup with the new credentials
        displayCredentials(accountId, roleName,
          data.Credentials.AccessKeyId,
          data.Credentials.SecretAccessKey,
          data.Credentials.SessionToken,
          data.Credentials.Expiration);
      })
      .catch((err) => {
        const message = err.message ? err.message : JSON.stringify(err, null, 2);
        alert(message);
      });
  }

  /**
   * Find the ARN of the IDP associated with the specified role
   *
   * The SAML XML contains a list of IDP and Role ARNs inside an attribute tag
   * https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html
   */
  function getIDPForRole($saml, role) {
    const $attribute = $saml.find('[Name=\'https://aws.amazon.com/SAML/Attributes/Role\']')
      .filter((idx, element) => {
        return element.localName === 'Attribute' && element.namespaceURI === 'urn:oasis:names:tc:SAML:2.0:assertion';
      });
    const $value = $attribute.find(':contains(\''+role+'\')')
      .filter((idx, element) => {
        return element.localName === 'AttributeValue' && element.namespaceURI === 'urn:oasis:names:tc:SAML:2.0:assertion';
      });

    if(!$value || !$value.length) {
      throw new Error('Failed to find IDP ARN for selected role: '+role);
    }

    // IDP is usually the first part, but not always
    var parts = $value.text().split(',');
    if(parts[0].indexOf(':saml-provider/') !== -1) {
      return parts[0];
    } else {
      return parts[1];
    }
  }

  /**
   * Find the Session Duration to use for temporary AWS access keys
   * Note: There is no easy way for this code to know exactly what duration the
   * role allows.  Selecting a duration that is too long gives an error
   *
   * Values are selected with the following preference:
   * 1) Override value specified in SESSION_DURATION_OVERRIDES above
   * 2) SessionDuration attribute specified within SAML token
   * 3) Default value of 1 hour
   */
  function getSessionDurationForRole($saml, role) {

    // Override value specified in SESSION_DURATION_OVERRIDES above
    if( SESSION_DURATION_OVERRIDES[role] ) {
      return SESSION_DURATION_OVERRIDES[role];
    }

    // SessionDuration attribute specified within SAML token
    try {

      const $attribute = $saml.find('[Name=\'https://aws.amazon.com/SAML/Attributes/SessionDuration\']')
      .filter((idx, element) => {
        return element.localName === 'Attribute' && element.namespaceURI === 'urn:oasis:names:tc:SAML:2.0:assertion';
      });
      
      if( $attribute && $attribute.length ) {
        const duration = $attribute.children(':first').text();
        if(duration >= 900 && duration <= 43200) { // allowed values are between 15 minutes and 12 hours
          return duration;
        }
      }
    } catch(err) {
      console.warn('Was not able to read SessionDuration attribute from SAML token');
      // Fall through to default value below
    }

    // Default value of 1 hour
    return 3600;
  }


  /**
   * Render a modal popup to display the AWS Access keys
   */
  function displayCredentials(accountNumber, roleName, accessKey, secretAccessKey, sessionToken, expiration) {
    const expireTime = new Date(expiration).toLocaleTimeString();

    const storage = window.localStorage;
    const defaultProfileName = `${accountNumber}-${roleName}`;
    const profileName = storage.getItem(defaultProfileName) ? storage.getItem(defaultProfileName) : defaultProfileName;

    // HTML that forms the popup UI.  Note that styles are added via GM_addStyle further down
    const popupHTML = `
      <div id="backdrop">
        <div id="credentials">
          <div class="title">AWS Credentials for ${roleName}</div>
          <div class="expiration">Credentials will expire at <b>${expireTime}</b></div>
          <div class="option">Option 1: Set AWS environment variables</div>
          <p>Paste the following commands in your command line to set the AWS environment variables.
            <a href="https://docs.aws.amazon.com/console/singlesignon/user-portal/aws-accounts/command-line/get-credentials/option1">Learn More</a>
          </p>
          <div id="tabs">
            <ul>
              <li><a href="#linux">MacOS or Linux</a></li>
              <li><a href="#windows">Windows CMD</a></li>
              <li><a href="#powershell">PowerShell</a></li>
            </ul>
            <div class="codepanel" id="linux">
              <textarea class="code-box" rows="3" spellcheck="false" readonly>export AWS_ACCESS_KEY_ID="${accessKey}"
export AWS_SECRET_ACCESS_KEY="${secretAccessKey}"
export AWS_SESSION_TOKEN="${sessionToken}"</textarea>
            </div>
            <div class="codepanel" id="windows">
              <textarea class="code-box" rows="3" spellcheck="false" readonly>set AWS_ACCESS_KEY_ID="${accessKey}"
set AWS_SECRET_ACCESS_KEY="${secretAccessKey}"
set AWS_SESSION_TOKEN="${sessionToken}"</textarea>
            </div>
            <div class="codepanel" id="powershell">
              <textarea class="code-box" rows="3" spellcheck="false" readonly>Set-AWSCredential -AccessKey "${accessKey}" \`
-SecretKey "${secretAccessKey}" \`
-SessionToken "${sessionToken}"</textarea>
            </div>
          </div>
          <div class="option">Option 2: Add a profile to your AWS credentials file</div>
          <p>Paste the following commands into your command line to update your AWS credentials file (typically found at ~/.aws/credentials).
            <a href="https://docs.aws.amazon.com/console/singlesignon/user-portal/aws-accounts/command-line/get-credentials/option2">Learn More</a>
          </p>
          <p>
            &nbsp;&nbsp;&nbsp; Profile Name: <input id="profileInput" type="text" value="${profileName}" spellcheck="false">
          </p>
          <div class="codepanel">
            <textarea class="code-box" id="option2" rows="4" spellcheck="false" readonly>aws configure set profile.${profileName}.aws_access_key_id "${accessKey}"
aws configure set profile.${profileName}.aws_secret_access_key "${secretAccessKey}"
aws configure set profile.${profileName}.aws_session_token "${sessionToken}"</textarea>
          </div>
          <div class="option">Option 3: Use individual values in your AWS service client</div>
          <div id="raw-values">
            <span>AWS Access Key Id</span>
            <input type="text" value="${accessKey}" readonly spellcheck="false">
            <span>AWS Secret Access Key</span>
            <input type="text" value="${secretAccessKey}" readonly spellcheck="false">
            <span>AWS Session Token</span>
            <input type="text" value="${sessionToken}" readonly spellcheck="false">
          </div>
        </div>
      </div>`;

    // Remember which platform option the user has selected
    const TAB_SELECTION_KEY = 'envvar/tab/selected';
    let activeTab = 0;
    try {
      activeTab = storage.getItem(TAB_SELECTION_KEY);
    } catch(err) {} // Not a big deal if we can't recall the user's selection
    function onTabChange(event, ui) {
      var tabIndex = ui.newTab.parent().children().index(ui.newTab);
      storage.setItem(TAB_SELECTION_KEY, tabIndex);
    }
    function onProfileChange() {
      const newProfileName = $('#profileInput').val();
      
      $('#option2').val(
        `aws configure set profile.${newProfileName}.aws_access_key_id "${accessKey}"
aws configure set profile.${newProfileName}.aws_secret_access_key "${secretAccessKey}"
aws configure set profile.${newProfileName}.aws_session_token "${sessionToken}"`);

      storage.setItem(defaultProfileName, newProfileName);
    }


    const popup = $(popupHTML);
    $('body').append(popup);
    $('#tabs').tabs({active: activeTab, activate: onTabChange});
    $('#profileInput').on('input', onProfileChange);
    $('#credentials').click((event)=> { event.stopPropagation(); });
    $('#backdrop').scroll((event)=> { event.stopPropagation(); });
    $('#backdrop').click(()=> { $('#backdrop').remove(); });
  }


  // Load Custom Styles required by the credentials popup
  GM_addStyle( GM_getResourceText('JQUI-CSS'));
  GM_addStyle ( `
    #backdrop {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: #333333DD;
    }
    #tabs a:focus {
      outline: 0;
    }
    #credentials {
      max-height: max-content;
      position: fixed;
      overflow-y: scroll;
      top: 20px;
      left: 50%;
      bottom: 20px;
      min-height: 200px;
      transform: translate(-50%,0);
      -ms-transform: translate(-50%,0);
      margin: 20px auto;
      background: #FFF;
      border: 1px solid #BBB;
      padding: 20px 10px;
      font-size: 14px;
    }
    #credentials > .title {
      font-size: 20px;
      font-weight: bold;
      margin-bottom: 20px;
      text-align: center;
    }
    #credentials > .expiration {
      text-align: center;
    }
    #credentials > .option {
      padding-top: 20px;
      font-size: 16px;
      font-weight: bold;
      border-top: 1px solid #CCC;
      margin-top: 10px;
    }

    #tabs {
      background: transparent;
      border: none;
      padding-top: 0px;
      margin-top: -10px;
    }
    #tabs .ui-widget-header {
      background: transparent;
      border: none;
      -moz-border-radius: 0px;
      -webkit-border-radius: 0px;
      border-radius: 0px;
    }
    #tabs .ui-tabs-nav .ui-state-default {
      background: transparent;
      border: none;
    }
    #tabs .ui-tabs-nav .ui-state-active {
      background: transparent;
      border: none;
    }
    #tabs .ui-tabs-nav .ui-state-default a {
      color: #c0c0c0;
    }
    #tabs .ui-tabs-nav .ui-state-active a {
      color: #FF9900;
    }
    #tabs .ui-tabs-panel {
      padding: 0;
      padding-left: 10px;
    }

    #raw-values {
      display: grid;
      grid-template-columns: max-content auto;
      grid-row-gap: 8px;
      grid-column-gap: 6px;
      padding-top: 10px;
    }
    #raw-values span {
      padding-top: 10px;
    }
    input {
      background: #FAFAFA;
      padding: 4px 10px;
      border-left: solid 3px #FF9900;
      border-top: 1px solid #c0c0c0;
      margin: 0px;
      unicode-bidi: embed;
      font-family: monospace !important;
      white-space: pre;
      font-size: 1em;
      width: 520px;
    }

    .code-box {
      unicode-bidi: embed;
      font-family: monospace !important;
      white-space: pre;
      font-size: 1em;
      width: 675px;
      height: auto;
      resize: none;
      border: 0;
      background: #FAFAFA;
      padding: 10px;
      border-left: solid 3px #FF9900;
      border-top: 1px solid #c0c0c0;
      margin: 0px;
      overflow-x: hidden;
    }

    .codepanel {
      position: relative;
      padding-left: 10px;
    }`);

})();
