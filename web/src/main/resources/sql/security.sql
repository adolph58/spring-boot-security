/*
Navicat MySQL Data Transfer

Source Server         : 54-5.7-3307
Source Server Version : 50725
Source Host           : 192.168.1.54:3307
Source Database       : security

Target Server Type    : MYSQL
Target Server Version : 50725
File Encoding         : 65001

Date: 2019-04-30 17:47:56
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for `department`
-- ----------------------------
DROP TABLE IF EXISTS `department`;
CREATE TABLE `department` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `createdate` datetime DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Records of department
-- ----------------------------
INSERT INTO `department` VALUES ('1', null, '开发部');

-- ----------------------------
-- Table structure for `persistent_logins`
-- ----------------------------
DROP TABLE IF EXISTS `persistent_logins`;
CREATE TABLE `persistent_logins` (
  `series` varchar(64) NOT NULL,
  `last_used` datetime NOT NULL,
  `token` varchar(64) NOT NULL,
  `username` varchar(64) NOT NULL,
  PRIMARY KEY (`series`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Records of persistent_logins
-- ----------------------------
INSERT INTO `persistent_logins` VALUES ('nsu5krgNg2EQwhp0S3FrgA==', '2019-04-08 11:55:35', 'aDQPbJlbbmIVhOeyAjZ3Qg==', 'user');

-- ----------------------------
-- Table structure for `role`
-- ----------------------------
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `createdate` datetime DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Records of role
-- ----------------------------
INSERT INTO `role` VALUES ('1', null, 'admin');

-- ----------------------------
-- Table structure for `user`
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `createdate` datetime DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `sex` int(11) DEFAULT NULL,
  `did` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FK_r9sq2o8fywkfnac3ekee0d6l4` (`did`),
  CONSTRAINT `FK_r9sq2o8fywkfnac3ekee0d6l4` FOREIGN KEY (`did`) REFERENCES `department` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES ('1', '2019-04-08 11:54:34', null, 'user', '$2a$10$9CMbLYzXNS9tdr6DaECWv.1zlzVinpHIZv0dob50X3G0wt/n2A.ni', null, '1');

-- ----------------------------
-- Table structure for `user_role`
-- ----------------------------
DROP TABLE IF EXISTS `user_role`;
CREATE TABLE `user_role` (
  `user_id` bigint(20) NOT NULL,
  `roles_id` bigint(20) NOT NULL,
  KEY `FK_5k3dviices5fr7560hvc81x4r` (`roles_id`),
  KEY `FK_apcc8lxk2xnug8377fatvbn04` (`user_id`),
  CONSTRAINT `FK_5k3dviices5fr7560hvc81x4r` FOREIGN KEY (`roles_id`) REFERENCES `role` (`id`),
  CONSTRAINT `FK_apcc8lxk2xnug8377fatvbn04` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Records of user_role
-- ----------------------------
INSERT INTO `user_role` VALUES ('1', '1');
