/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 1997-2010 Oracle and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://glassfish.dev.java.net/public/CDDL+GPL_1_1.html
 * or packager/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at packager/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * Oracle designates this particular file as subject to the "Classpath"
 * exception as provided by Oracle in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */
package pl.pcss.nds.ndsrealm;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;
import java.util.logging.Level;
import javax.sql.DataSource;
import com.sun.appserv.connectors.internal.api.ConnectorRuntime;

import javax.security.auth.login.LoginException;
import com.sun.enterprise.security.auth.realm.IASRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.digest.api.DigestAlgorithmParameter;
import com.sun.enterprise.security.auth.realm.DigestRealmBase;
import com.sun.enterprise.security.common.Util;
import java.sql.SQLException;
import javax.naming.NamingException;
import org.jvnet.hk2.annotations.Service;

/**
 * Realm for supporting JDBC authentication.
 *
 * <P>
 * The JDBC realm needs the following properties in its configuration:
 * <ul>
 * <li>jaas-context : JAAS context name used to access LoginModule for
 * authentication (for example NdsRealm).
 * <li>datasource-jndi : jndi name of datasource
 * <li>group-table: table containing user name and group name
 * group-table
 * <li>group-name-column : column corresponding to group in group-table
 * </ul>
 *
 * @see com.sun.enterprise.security.auth.login.SolarisLoginModule
 *
 */
@Service
public final class NdsRealm extends DigestRealmBase {

    // Descriptive string of the authentication type of this realm.

    /**
     *
     */
        public static final String AUTH_TYPE = "jdbc";

    /**
     *
     */
    public static final String PARAM_DATASOURCE_JNDI = "datasource-jndi";

    /**
     *
     */
    public static final String NONE = "none";

    /**
     *
     */
    public static final String PARAM_ENCODING = "encoding";

    /**
     *
     */
    public static final String PARAM_GROUP_TABLE = "group-table";

    /**
     *
     */
    public static final String PARAM_GROUP_NAME_COLUMN = "group-name-column";

    /**
     *
     */
    public static final String PARAM_GROUP_TABLE_USER_NAME_COLUMN = "group-table-user-name-column";

    private Map<String, Vector> groupCache;
    private Vector<String> emptyVector;
    private static final String PARAM_DB_USER = "db-user";
    private static String PARAM_DB_PASSWORD = "db-password";

    private ConnectorRuntime cr;

    /**
     * Initialize a realm with some properties. This can be used when
     * instantiating realms from their descriptions. This method may only be
     * called a single time.
     *
     * @param props Initialization parameters used by this realm.
     * @exception BadRealmException If the configuration parameters identify a
     * corrupt realm.
     * @exception NoSuchRealmException If the configuration parameters specify a
     * realm which doesn't exist.
     */
    @Override
    public synchronized void init(Properties props)
            throws BadRealmException, NoSuchRealmException {
        super.init(props);
        String jaasCtx = props.getProperty(IASRealm.JAAS_CONTEXT_PARAM);
        String dsJndi = props.getProperty(PARAM_DATASOURCE_JNDI);
        String groupTable = props.getProperty(PARAM_GROUP_TABLE);
        String groupNameColumn = props.getProperty(PARAM_GROUP_NAME_COLUMN);
        String groupTableUserNameColumn = props.getProperty(PARAM_GROUP_TABLE_USER_NAME_COLUMN);
        cr = Util.getDefaultHabitat().getByContract(ConnectorRuntime.class);

        if (jaasCtx == null) {
            String msg = sm.getString(
                    "realm.missingprop", IASRealm.JAAS_CONTEXT_PARAM, "JDBCRealm");
            throw new BadRealmException(msg);
        }

        this.setProperty(IASRealm.JAAS_CONTEXT_PARAM, jaasCtx);

        if (dsJndi == null) {
            String msg = sm.getString(
                    "realm.missingprop", PARAM_DATASOURCE_JNDI, "JDBCRealm");
            throw new BadRealmException(msg);
        }

        this.setProperty(PARAM_DATASOURCE_JNDI, dsJndi);

        if (groupTable == null) {
            String msg = sm.getString(
                    "realm.missingprop", PARAM_GROUP_TABLE, "JDBCRealm");
            throw new BadRealmException(msg);
        }

        this.setProperty(PARAM_GROUP_TABLE, groupTable);

        if (groupNameColumn == null) {
            String msg = sm.getString(
                    "realm.missingprop", PARAM_GROUP_NAME_COLUMN, "JDBCRealm");
            throw new BadRealmException(msg);
        }

        this.setProperty(PARAM_GROUP_NAME_COLUMN, groupNameColumn);

        if (groupTableUserNameColumn == null) {
            String msg = sm.getString(
                    "realm.missingprop", PARAM_GROUP_TABLE_USER_NAME_COLUMN, "JDBCRealm");
            throw new BadRealmException(msg);
        }

        this.setProperty(PARAM_GROUP_TABLE_USER_NAME_COLUMN, groupTableUserNameColumn);

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.log(Level.FINEST,"JDBCRealm : " + IASRealm.JAAS_CONTEXT_PARAM + "= {0}"
                    + ", " + PARAM_DATASOURCE_JNDI + " = {1}", new Object[]{jaasCtx, dsJndi});
        }

        groupCache = new HashMap<String, Vector>();
        emptyVector = new Vector<String>();
    }

    /**
     * Returns a short (preferably less than fifteen characters) description of
     * the kind of authentication which is supported by this realm.
     *
     * @return Description of the kind of authentication that is directly
     * supported by this realm.
     */
    @Override
    public String getAuthType() {
        return AUTH_TYPE;
    }

    /**
     * Returns the name of all the groups that this user belongs to. It loads
     * the result from groupCache first. This is called from web path group
     * verification, though it should not be.
     *
     * @param username Name of the user in this realm whose group listing is
     * needed.
     * @return Enumeration of group names (strings).
     * @exception InvalidOperationException thrown if the realm does not support
     * this operation - e.g. Certificate realm does not support this operation.
     * @throws com.sun.enterprise.security.auth.realm.NoSuchUserException
     */
    @Override
    public Enumeration getGroupNames(String username)
            throws InvalidOperationException, NoSuchUserException {
        Vector vector = groupCache.get(username);
        if (vector == null) {
            String[] grps = findGroups(username);
            setGroupNames(username, grps);
            vector = groupCache.get(username);
        }
        return vector.elements();
    }

    private void setGroupNames(String username, String[] groups) {
        Vector<String> v = null;

        if (groups == null) {
            v = emptyVector;

        } else {
            v = new Vector<String>(groups.length + 1);
            for (int i = 0; i < groups.length; i++) {
                v.add(groups[i]);
            }
        }

        synchronized (this) {
            groupCache.put(username, v);
        }
    }

    /**
     * Invoke the native authentication call.
     *
     * @param username User to authenticate.
     * @param password Given password.
     * @return list of groups
     *
     */
    public String[] authenticate(String username, char[] password) {
        String[] groups = null;
        if (isUserValid(username, password)) {
            groups = findGroups(username);
            groups = addAssignGroups(groups);
            setGroupNames(username, groups);
        }
        return groups;
    }

    /**
     * Test if a user is valid
     *
     * @param user user's identifier
     * @param password user's password
     * @return true if valid
     */
    private boolean isUserValid(String user, char[] password) {
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        boolean valid = false;
        this.setProperty(PARAM_DB_USER, user);
        this.setProperty(PARAM_DB_PASSWORD, String.valueOf(password));

        try {
            connection = getConnection();

        } catch (LoginException ex) {
            _logger.log(Level.SEVERE, "ndscrealm.invaliduser", user);
            if (_logger.isLoggable(Level.FINE)) {
                _logger.log(Level.FINE, "Cannot validate user", ex);
            }
        } finally {
            close(connection, statement, rs);
        }
        if (connection != null) {
            valid = true;
        }
        return valid;
    }

    /**
     * Delegate method for retreiving users groups
     *
     * @param user user's identifier
     * @return array of group key
     */
    private String[] findGroups(String user) {
        String groupTable = this.getProperty(PARAM_GROUP_TABLE);
        String groupNameColumn = this.getProperty(PARAM_GROUP_NAME_COLUMN);
        String groupTableUserNameColumn = this.getProperty(PARAM_GROUP_TABLE_USER_NAME_COLUMN);
        String groupQuery;

        groupQuery = "SELECT " + groupNameColumn + " FROM " + groupTable
                + " WHERE " + groupTableUserNameColumn + " = ? ";

        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            connection = getConnection();
            statement = connection.prepareStatement(groupQuery);
            statement.setString(1, user);
            rs = statement.executeQuery();
            final List<String> groups = new ArrayList<String>();
            while (rs.next()) {
                groups.add(rs.getString(1));
            }
            final String[] groupArray = new String[groups.size()];
            return groups.toArray(groupArray);
        } catch (SQLException ex) {
            _logger.log(Level.SEVERE, "ndscrealm.grouperror", user);
            if (_logger.isLoggable(Level.FINE)) {
                _logger.log(Level.FINE, "Cannot load group", ex);
            }
            return null;
        } catch (LoginException ex) {
            _logger.log(Level.SEVERE, "ndscrealm.grouperror", user);
            if (_logger.isLoggable(Level.FINE)) {
                _logger.log(Level.FINE, "Cannot load group", ex);
            }
            return null;
        }       
        finally {
            close(connection, statement, rs);
        }
    }

    private void close(Connection conn, PreparedStatement stmt,
            ResultSet rs) {
        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException ex) {
            }
        }

        if (stmt != null) {
            try {
                stmt.close();
            } catch (SQLException ex) {
            }
        }

        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException ex) {
            }
        }
    }

    /**
     * Return a connection from the properties configured
     *
     * @return a connection
     */
    private Connection getConnection() throws LoginException {
        final String dsJndi = this.getProperty(PARAM_DATASOURCE_JNDI);
        final String dbUser = this.getProperty(PARAM_DB_USER);
        final String dbPassword = this.getProperty(PARAM_DB_PASSWORD);
        try {
            String nonTxJndiName = dsJndi + "__nontx";
            final DataSource dataSource
                    = (DataSource) cr.lookupNonTxResource(dsJndi, false);
            Connection connection = null;

            if (dbUser != null && dbPassword != null) {                
                connection = dataSource.getConnection(dbUser, dbPassword);
            } else {
                connection = dataSource.getConnection();
            }            
            return connection;
        } catch (NamingException  ex) {
            String msg = sm.getString("ndsrealm.cantconnect", dsJndi, dbUser);
            LoginException loginEx = new LoginException(msg);
            loginEx.initCause(ex);
            throw loginEx;
        }
        catch ( SQLException ex) {
            String msg = sm.getString("ndsrealm.cantconnect", dsJndi, dbUser);
            LoginException loginEx = new LoginException(msg);
            loginEx.initCause(ex);
            throw loginEx;
        }
    }

    /**
     *
     * @param string
     * @param daps
     * @return
     */
    @Override
    public boolean validate(String string, DigestAlgorithmParameter[] daps) {
        _logger.log(Level.WARNING, "NdsRealm: validate UserRealm");
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
