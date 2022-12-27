INSERT INTO roles(name) VALUES ("ROLE_USER");
INSERT INTO roles(name) VALUES ("ROLE_ADMIN");

-- password = admin
INSERT INTO users(email, first_name, last_name, age, password) VALUES ("nwhite@mail.ru", "Nicholas", "White", 48, "$2a$10$eMMWx/ClHfHx8shzzcq5..cG0.brwg4shEYay1sr65rXPxJzek9La");
-- password = helen
INSERT INTO users(email, first_name, last_name, age, password) VALUES("helen@mail.ru", "Helen", "Petrovsky", 25, "$2a$10$Bowq4j4QpO06qxWy5oTwmesQ.YxHHx2TQurVNLwtQlkKj9IKujcGO");
-- password = arthur
INSERT INTO users(email, first_name, last_name, age, password) VALUES("arthur@gmail.com", "Arthur", "Peck", 35, "$2a$10$XsOuaFFUMaZctmm1V8/sSOevKN3CxVdUuKi6Xf8iVJ7egbUkxEwNu");

INSERT INTO user_role(user_id, role_id) VALUES (1, 1);
INSERT INTO user_role(user_id, role_id) VALUES (1, 2);
INSERT INTO user_role(user_id, role_id) VALUES (2, 1);
INSERT INTO user_role(user_id, role_id) VALUES (3, 1);
