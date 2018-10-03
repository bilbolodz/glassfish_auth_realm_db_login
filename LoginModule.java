/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pl.pcss.nds.ndsrealm;

import com.sun.appserv.security.AppservPasswordLoginModule;
import java.util.logging.Level;

import com.sun.enterprise.security.auth.login.common.LoginException;
import java.util.Arrays;

/**
 *
 * @author bilbo
 */
public class LoginModule extends AppservPasswordLoginModule {     
    @Override
    /**
     * Perform JDBC authentication. Delegates to JDBCRealm.
     *
     * @throws LoginException If login fails (JAAS login() behavior).
     */    
    protected void authenticateUser() throws LoginException {
 
        if (!(_currentRealm instanceof NdsRealm)) {
            String msg = sm.getString("userloginmodule.badrealm");
            throw new LoginException(msg);
        }
        
        final NdsRealm jdbcRealm = (NdsRealm)_currentRealm;

        // A JDBC user must have a name not null and non-empty.
        if ( (_username == null) || (_username.length() == 0) ) {
            String msg = sm.getString("userloginmodule.nulluser");
            throw new LoginException(msg);
        }
        
        String[] grpList = jdbcRealm.authenticate(_username, getPasswordChar());

        if (grpList == null) {  // JAAS behavior
            String msg = sm.getString("userloginmodule.loginfail", _username);
            throw new LoginException(msg);
        }

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.log(Level.FINEST, "JDBC (NdsRealm) login succeeded for: {0} groups:{1}", new Object[]{_username, Arrays.toString(grpList)});
        }
        commitUserAuthentication(grpList);      
    }    
}
