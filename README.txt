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

