package com.macro.mall.common.constant;

/**
 * 权限相关常量定义
 * Created by macro on 2020/6/19.
 */
public interface AuthConstant {

    /**
     * JWT存储权限前缀
     */
    String AUTHORITY_PREFIX = "ROLE_";

    /**
     * JWT存储权限属性
     */
    String AUTHORITY_CLAIM_NAME = "authorities";

    /**
     * 后台管理client_id
     */
    String ADMIN_CLIENT_ID = "admin-app";

    /**
     * 前台商城client_id
     */
    String PORTAL_CLIENT_ID = "portal-app";

    /**
     * 后台管理接口路径匹配
     */
    String ADMIN_URL_PATTERN = "/mall-admin/**";

    /**
     * Redis缓存权限规则（路径->资源）
     */
    String PATH_RESOURCE_MAP = "auth:pathResourceMap";

    /**
     * 认证信息Http请求头
     */
    String JWT_TOKEN_HEADER = "Authorization";

    /**
     * JWT令牌前缀
     */
    String JWT_TOKEN_PREFIX = "Bearer ";

    /**
     * 用户信息Http请求头
     */
    String USER_TOKEN_HEADER = "user";

    /**
     * 网关向下传递的用户ID请求头
     */
    String USER_ID_HEADER = "X-User-Id";

    /**
     * 网关向下传递的用户类型请求头
     */
    String USER_TYPE_HEADER = "X-User-Type";

    /**
     * 网关向下传递的用户名请求头
     */
    String USERNAME_HEADER = "X-Username";

    /**
     * 网关向下传递的用户权限请求头
     */
    String PERMISSIONS_HEADER = "X-User-Permissions";

}
