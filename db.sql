CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  username VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  is_2fa_enabled BOOLEAN DEFAULT FALSE
)

INSERT INTO users (name, username, password, email, is_2fa_enabled) VALUES ('admin', 'admin', 'admin', 'admin@gmail.com');