-- Sample seed data (same for both vulnerable and safe databases)

INSERT INTO users (username, password, email, full_name, role) VALUES
('admin', 'Admin@12345', 'admin@fastedu.pk', 'Portal Administrator', 'admin'),
('saqlain', 'Student@123', 'saqlain@fastedu.pk', 'Saqlain Amjad', 'student'),
('ali khan', 'Student@123', 'khan@fastedu.pk', 'ali Khan', 'student');

INSERT INTO courses (code, title, instructor, description) VALUES
('CS4063', 'Natural Language Processing', 'Dr. Ghous', 'Covers classical and neural approaches to NLP, including transformers and LLMs.'),
('CS4057', 'Information Security', 'Dr. Imran', 'Introduces offensive and defensive web security concepts (this project!).'),
('CS3005', 'Database Systems', 'Dr. Saira', 'Relational database design, SQL, normalization and transactions.'),
('CS4062', 'Computer Vision', 'Dr. Ghous', 'Image processing, object detection and deep-learning based vision pipelines.');

INSERT INTO reviews (course_id, user_id, author_name, comment) VALUES
(1, 2, 'Saqlain Amjad', 'Great course, the transformer assignments were tough but rewarding.'),
(2, 3, 'ali Khan', 'This is exactly the course that inspired our security project!'),
(3, 2, 'Saqlain Amjad', 'Solid fundamentals, the normalization labs were very useful.');
