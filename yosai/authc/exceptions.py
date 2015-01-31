/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc;

/**
 * Exception thrown due to a problem with the account
 * under which an authentication attempt is being executed.
 *
 * @since 0.1
 */
public class AccountException extends AuthenticationException {

    /**
     * Creates a new AccountException.
     */
    public AccountException() {
        super();
    }

    /**
     * Constructs a new AccountException.
     *
     * @param message the reason for the exception
     */
    public AccountException(String message) {
        super(message);
    }

    /**
     * Constructs a new AccountException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public AccountException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new AccountException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public AccountException(String message, Throwable cause) {
        super(message, cause);
    }

}
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc;

import org.apache.shiro.ShiroException;


/**
 * General exception thrown due to an error during the Authentication process.
 *
 * @since 0.1
 */
public class AuthenticationException extends ShiroException
{

    /**
     * Creates a new AuthenticationException.
     */
    public AuthenticationException() {
        super();
    }

    /**
     * Constructs a new AuthenticationException.
     *
     * @param message the reason for the exception
     */
    public AuthenticationException(String message) {
        super(message);
    }

    /**
     * Constructs a new AuthenticationException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public AuthenticationException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new AuthenticationException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc;

/**
 * Thrown when an authentication attempt has been received for an account that has already been
 * authenticated (i.e. logged-in), and the system is configured to prevent such concurrent access.
 *
 * <p>This is useful when an application must ensure that only one person is logged-in to a single
 * account at any given time.
 *
 * <p>Sometimes account names and passwords are lazily given away
 * to many people for easy access to a system.  Such behavior is undesirable in systems where
 * users are accountable for their actions, such as in government applications, or when licensing
 * agreements must be maintained, such as those which only allow 1 user per paid license.
 *
 * <p>By disallowing concurrent access, such systems can ensure that each authenticated session
 * corresponds to one and only one user at any given time.
 *
 * @since 0.1
 */
public class ConcurrentAccessException extends AccountException {

    /**
     * Creates a new ConcurrentAccessException.
     */
    public ConcurrentAccessException() {
        super();
    }

    /**
     * Constructs a new ConcurrentAccessException.
     *
     * @param message the reason for the exception
     */
    public ConcurrentAccessException(String message) {
        super(message);
    }

    /**
     * Constructs a new ConcurrentAccessException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ConcurrentAccessException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ConcurrentAccessException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public ConcurrentAccessException(String message, Throwable cause) {
        super(message, cause);
    }

}
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc;

/**
 * Exception thrown due to a problem with the credential(s) submitted for an
 * account during the authentication process.
 *
 * @since 0.1
 */
public class CredentialsException extends AuthenticationException {

    /**
     * Creates a new CredentialsException.
     */
    public CredentialsException() {
        super();
    }

    /**
     * Constructs a new CredentialsException.
     *
     * @param message the reason for the exception
     */
    public CredentialsException(String message) {
        super(message);
    }

    /**
     * Constructs a new CredentialsException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public CredentialsException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new CredentialsException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public CredentialsException(String message, Throwable cause) {
        super(message, cause);
    }

}
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc;

/**
 * Thrown when attempting to authenticate and the corresponding account has been disabled for
 * some reason.
 *
 * @see LockedAccountException
 * @since 0.1
 */
public class DisabledAccountException extends AccountException {

    /**
     * Creates a new DisabledAccountException.
     */
    public DisabledAccountException() {
        super();
    }

    /**
     * Constructs a new DisabledAccountException.
     *
     * @param message the reason for the exception
     */
    public DisabledAccountException(String message) {
        super(message);
    }

    /**
     * Constructs a new DisabledAccountException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public DisabledAccountException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new DisabledAccountException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public DisabledAccountException(String message, Throwable cause) {
        super(message, cause);
    }
}
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc;

/**
 * Thrown when a system is configured to only allow a certain number of authentication attempts
 * over a period of time and the current session has failed to authenticate successfully within
 * that number.  The resulting action of such an exception is application-specific, but
 * most systems either temporarily or permanently lock that account to prevent further
 * attempts.
 *
 * @since 0.1
 */
public class ExcessiveAttemptsException extends AccountException {

    /**
     * Creates a new ExcessiveAttemptsException.
     */
    public ExcessiveAttemptsException() {
        super();
    }

    /**
     * Constructs a new ExcessiveAttemptsException.
     *
     * @param message the reason for the exception
     */
    public ExcessiveAttemptsException(String message) {
        super(message);
    }

    /**
     * Constructs a new ExcessiveAttemptsException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ExcessiveAttemptsException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ExcessiveAttemptsException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public ExcessiveAttemptsException(String message, Throwable cause) {
        super(message, cause);
    }
}
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc;

/**
 * Thrown during the authentication process when the system determines the submitted credential(s)
 * has expired and will not allow login.
 *
 * <p>This is most often used to alert a user that their credentials (e.g. password or
 * cryptography key) has expired and they should change the value.  In such systems, the component
 * invoking the authentication might catch this exception and redirect the user to an appropriate
 * view to allow them to update their password or other credentials mechanism.
 *
 * @since 0.1
 */
public class ExpiredCredentialsException extends CredentialsException {

    /**
     * Creates a new ExpiredCredentialsException.
     */
    public ExpiredCredentialsException() {
        super();
    }

    /**
     * Constructs a new ExpiredCredentialsException.
     *
     * @param message the reason for the exception
     */
    public ExpiredCredentialsException(String message) {
        super(message);
    }

    /**
     * Constructs a new ExpiredCredentialsException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ExpiredCredentialsException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ExpiredCredentialsException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public ExpiredCredentialsException(String message, Throwable cause) {
        super(message, cause);
    }
}
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc;

/**
 * Thrown when attempting to authenticate with credential(s) that do not match the actual
 * credentials associated with the account principal.
 *
 * <p>For example, this exception might be thrown if a user's password is &quot;secret&quot; and
 * &quot;secrets&quot; was entered by mistake.
 *
 * <p>Whether or not an application wishes to let
 * the user know if they entered incorrect credentials is at the discretion of those
 * responsible for defining the view and what happens when this exception occurs.
 *
 * @since 0.1
 */
public class IncorrectCredentialsException extends CredentialsException {

    /**
     * Creates a new IncorrectCredentialsException.
     */
    public IncorrectCredentialsException() {
        super();
    }

    /**
     * Constructs a new IncorrectCredentialsException.
     *
     * @param message the reason for the exception
     */
    public IncorrectCredentialsException(String message) {
        super(message);
    }

    /**
     * Constructs a new IncorrectCredentialsException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public IncorrectCredentialsException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new IncorrectCredentialsException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public IncorrectCredentialsException(String message, Throwable cause) {
        super(message, cause);
    }

}
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc;

/**
 * A special kind of <tt>DisabledAccountException</tt>, this exception is thrown when attempting
 * to authenticate and the corresponding account has been disabled explicitly due to being locked.
 *
 * <p>For example, an account can be locked if an administrator explicitly locks an account or
 * perhaps an account can be locked automatically by the system if too many unsuccessful
 * authentication attempts take place during a specific period of time (perhaps indicating a
 * hacking attempt).
 *
 * @since 0.1
 */
public class LockedAccountException extends DisabledAccountException {

    /**
     * Creates a new LockedAccountException.
     */
    public LockedAccountException() {
        super();
    }

    /**
     * Constructs a new LockedAccountException.
     *
     * @param message the reason for the exception
     */
    public LockedAccountException(String message) {
        super(message);
    }

    /**
     * Constructs a new LockedAccountException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public LockedAccountException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new LockedAccountException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public LockedAccountException(String message, Throwable cause) {
        super(message, cause);
    }

}
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc;

/**
 * Thrown when attempting to authenticate with a principal that doesn't exist in the system (e.g.
 * by specifying a username that doesn't relate to a user account).
 *
 * <p>Whether or not an application wishes to alert a user logging in to the system of this fact is
 * at the discretion of those responsible for designing the view and what happens when this
 * exception occurs.
 *
 * @since 0.1
 */
public class UnknownAccountException extends AccountException {

    /**
     * Creates a new UnknownAccountException.
     */
    public UnknownAccountException() {
        super();
    }

    /**
     * Constructs a new UnknownAccountException.
     *
     * @param message the reason for the exception
     */
    public UnknownAccountException(String message) {
        super(message);
    }

    /**
     * Constructs a new UnknownAccountException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public UnknownAccountException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new UnknownAccountException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public UnknownAccountException(String message, Throwable cause) {
        super(message, cause);
    }
}
