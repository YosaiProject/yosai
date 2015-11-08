# ------------------------------------------------------------------------------
# Aggregate Permissions into a Permission Wildcard format
# ------------------------------------------------------------------------------

SELECT (
        CASE
            WHEN DOMAIN.name IS NULL THEN '*'
            ELSE DOMAIN.name
        END )
    || ':' || group_concat (
        DISTINCT (
            CASE
                WHEN ACTION.name IS NULL THEN '*'
                ELSE ACTION.name
            END ) )
    || ':' || group_concat (
        DISTINCT (
            CASE
                WHEN RESOURCE.name IS NULL THEN '*'
                ELSE RESOURCE.name
            END ) ) AS PERMISSION
FROM
    PERMISSION
    LEFT OUTER JOIN ACTION ON PERMISSION.action_id = ACTION.pk_id
    LEFT OUTER JOIN DOMAIN ON PERMISSION.domain_id = DOMAIN.pk_id
    LEFT OUTER JOIN RESOURCE ON PERMISSION.resource_id = RESOURCE.pk_id
GROUP BY
    PERMISSION.domain_id,
    PERMISSION.resource_id;


/*
domain                action      resource  
--------------------  ----------  ----------
*		      run         *
*                     bowl        *         
leatherduffelbag      transport   theringer 
leatherduffelbag      access      theringer 
money                 write       bankcheck_
money                 deposit     *         
money                 access      ransom    
money                 withdrawal  *   
*/