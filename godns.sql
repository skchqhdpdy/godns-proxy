-- 테이블 godns.ips 구조 내보내기
CREATE TABLE IF NOT EXISTS `ips` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `IP` char(39) NOT NULL,
  `memo` varchar(50) DEFAULT NULL,
  `server` varchar(50) DEFAULT 'ns.aodd.xyz',
  `count` int(11) NOT NULL DEFAULT 0,
  `Last_seen` bigint(20) NOT NULL DEFAULT unix_timestamp(),
  `blocked` tinyint(4) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `IP` (`IP`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;