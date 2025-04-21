update id2entry
set data = cast(
    json_replace(
        data,
        '$.ent.V3.attrs.acp_create_attr.I8',
        json_array(
            'class','description','displayname','image','name',
            'oauth2_allow_insecure_client_disable_pkce',
            'oauth2_allow_localhost_redirect',
            'oauth2_device_flow_enable',
            'oauth2_jwt_legacy_crypto_enable',
            'oauth2_prefer_short_username',
            'oauth2_rs_claim_map',
            'oauth2_rs_basic_secret',
            'oauth2_rs_name',
            'oauth2_rs_origin',
            'oauth2_rs_origin_landing',
            'oauth2_rs_scope_map',
            'oauth2_rs_sup_scope_map',
            'oauth2_strict_redirect_uri'
        )
    ) as blob
)
where cast (id as text) = (
    select json_extract(idl, '$.t.s[0]')
    from idx_eq_name
    where key = 'idm_acp_oauth2_manage'
);

update id2entry
set data = cast(
    json_replace(
        data,
        '$.ent.V3.attrs.acp_modify_presentattr.I8',
        json_array(
            'description','displayname','image','name',
            'oauth2_allow_insecure_client_disable_pkce',
            'oauth2_allow_localhost_redirect',
            'oauth2_device_flow_enable',
            'oauth2_jwt_legacy_crypto_enable',
            'oauth2_prefer_short_username',
            'oauth2_rs_claim_map',
            'oauth2_rs_basic_secret',
            'oauth2_rs_origin',
            'oauth2_rs_origin_landing',
            'oauth2_rs_scope_map',
            'oauth2_rs_sup_scope_map',
            'oauth2_strict_redirect_uri'
        )
    ) as blob
)
where cast (id as text) = (
    select json_extract(idl, '$.t.s[0]')
    from idx_eq_name
    where key = 'idm_acp_oauth2_manage'
);
