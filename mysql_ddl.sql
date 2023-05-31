-- Tables
CREATE TABLE IF NOT EXISTS `rp` (
  `id` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `icon` varchar(255),
  `description` varchar(4000),
  PRIMARY KEY pk_rp (`id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `user_key` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `rp_entity_id` varchar(255),
  `user_id` varchar(128) NOT NULL,
  `username` varchar(64) NOT NULL,
  `user_display_name` varchar(64) NOT NULL,
  `user_icon` varchar(128),
  `aaguid` varchar(36) NOT NULL,
  `credential_id` varchar(256) NOT NULL,
  `public_key` text NOT NULL,
  `signature_algorithm` integer NOT NULL,
  `sign_counter` bigint,
  `attestation_type` integer,
  `rk` tinyint(1),
  `cred_protect` integer,
  `authenticated_timestamp` datetime,
  `registered_timestamp` datetime,
  PRIMARY KEY pk_user_key (`id`),
  UNIQUE uk_user_key_rp_entity_id_credential_id (`rp_entity_id`, `credential_id`),
  INDEX idx_user_key_rp_entity_id_user_id (`rp_entity_id`, `user_id`),
  FOREIGN KEY fk_user_key_rp_entity_id (`rp_entity_id`) REFERENCES `rp`(`id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `authenticator_transport` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_key_id` bigint,
  `transport` varchar(4000) NOT NULL,
  PRIMARY KEY pk_authenticator_transport (`id`),
  FOREIGN KEY fk_authenticator_transport_user_key_id (`user_key_id`) REFERENCES `user_key`(`id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `metadata` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `aaguid` varchar(255),
  `content` text NOT NULL,
  `biometricStatusReports` text,
  `time_of_last_status_change` varchar(255),
  `status_reports` text,
  PRIMARY KEY pk_metadata (`id`),
  UNIQUE uk_metadata_aaguid (`aaguid`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `metadata_toc` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `metadata_source` text NOT NULL,
  `no` bigint NOT NULL,
  `legal_header` text,
  `next_update` varchar(255) NOT NULL,
  `encoded_metadata_toc_payload` text NOT NULL,
  PRIMARY KEY pk_metadata_toc (`id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `metadata_yubico` (
  `id` integer NOT NULL AUTO_INCREMENT,
  `content` text NOT NULL,
  PRIMARY KEY pk_metadata_yubico (`id`)
) ENGINE=InnoDB;

-- test rp
insert into `rp` (`id`, `name`, `description`) values('localhost', 'example1', 'example1');
