"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at
 
    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""

camelCase to under_score
------------------------
In several sections of the code, I automatically replaced camelCase code
with under_scored code using vim string replacement logic.  This may have
renamed a class by accident.


/this/self/ replacement
-----------------------
During the port, I automatically replaced 'this' with 'self'.  Due to this
string replacement, there may be incomprehensible comments in the code 
where 'self' should be changed back to 'this'


I am following J.B. Rainsberger's recommendation of rebranding unit and 
integration testing to isolated and integrated testing, respectively.


