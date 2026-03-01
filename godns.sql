-- 테이블 godns.filters 구조 내보내기
CREATE TABLE IF NOT EXISTS `filters` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(50) DEFAULT NULL,
  `value` varchar(50) NOT NULL,
  `blocked` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE KEY `value` (`value`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci ROW_FORMAT=DYNAMIC;

-- 테이블 godns.ips 구조 내보내기
CREATE TABLE IF NOT EXISTS `ips` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `IP` char(39) NOT NULL,
  `memo` varchar(50) DEFAULT NULL,
  `server` varchar(50) DEFAULT 'ns.aodd.xyz',
  `count` int(11) NOT NULL DEFAULT 0,
  `Last_seen` bigint(20) NOT NULL DEFAULT unix_timestamp(),
  `blocked` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE KEY `IP` (`IP`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci ROW_FORMAT=DYNAMIC;