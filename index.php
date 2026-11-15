<?php
session_start();
require_once "db.php";

$message = "";
$messageType = "";
$activeTab = "login";

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $action = $_POST['action'] ?? '';

    // LOGIN
    if ($action === "login") {

        $role = $_POST['role'] ?? '';
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($role === "admin") {

            $sql = "SELECT * FROM admins WHERE username = $1";
            $result = pg_query_params($conn, $sql, [$email]);

            if ($result && pg_num_rows($result) === 1) {

                $admin = pg_fetch_assoc($result);

                if (password_verify($password, $admin['password'])) {

                    session_regenerate_id(true);

                    $_SESSION['admin_id'] = $admin['admin_id'];
                    $_SESSION['username'] = $admin['username'];

                    header("Location: dashboard.php");
                    exit();

                } else {
                    $message = "Invalid password!";
                    $messageType = "error";
                }

            } else {
                $message = "Admin account not found!";
                $messageType = "error";
            }

        } elseif ($role === "student" || $role === "teacher") {

            $table = ($role === "student") ? "students" : "teachers";

            $sql = "SELECT * FROM $table WHERE LOWER(email) = LOWER($1)";

            $result = pg_query_params($conn, $sql, [$email]);

            if ($result && pg_num_rows($result) === 1) {

                $user = pg_fetch_assoc($result);

                if (!password_verify($password, $user['password'])) {

                    $message = "Incorrect password!";
                    $messageType = "error";

                } elseif (($user['status'] ?? '') !== 'approved') {

                    $message = "Your account is waiting for admin approval.";
                    $messageType = "error";

                } else {

                    session_regenerate_id(true);

                    $_SESSION['user_id'] =
                        $user[$role === "student" ? "student_id" : "teacher_id"];

                    $_SESSION['user_role'] = $role;
                    $_SESSION['user_name'] =
                        $user[$role === "student" ? "student_name" : "teacher_name"];

                    if ($role === "student") {
                        header("Location: student.php");
                    } else {
                        header("Location: teacher.php");
                    }

                    exit();
                }

            } else {
                $message = "Account not found!";
                $messageType = "error";
            }

        }

    }

    // REGISTRATION
    elseif ($action === "register") {

        $activeTab = "register";

        $role = $_POST['role'] ?? '';

        $name = trim($_POST['name'] ?? '');
        $email = strtolower(trim($_POST['email'] ?? ''));
        $password = $_POST['password'] ?? '';
        $confirm = $_POST['confirm_password'] ?? '';

        if (!hash_equals(
            $_SESSION['csrf_token'],
            $_POST['csrf_token'] ?? ''
        )) {

            $message = "Invalid request. Refresh the page.";
            $messageType = "error";

        } elseif (
            $name === '' ||
            !filter_var($email, FILTER_VALIDATE_EMAIL)
        ) {

            $message = "Please enter valid details.";
            $messageType = "error";

        } elseif ($password !== $confirm || strlen($password) < 8) {

            $message = "Check password. Minimum 8 characters required.";
            $messageType = "error";

        } else {

            $hashedPassword = password_hash(
                $password,
                PASSWORD_DEFAULT
            );

            if ($role === "student") {

                $roll = trim($_POST['roll_number'] ?? '');

                $check = pg_query_params(
                    $conn,
                    "SELECT student_id FROM students
                     WHERE email = $1 OR roll_number = $2",
                    [$email, $roll]
                );

                if ($roll === '' || !$check) {

                    $message = "Please enter a valid roll number.";
                    $messageType = "error";

                } elseif (pg_num_rows($check) > 0) {

                    $message = "Email or Roll Number already exists.";
                    $messageType = "error";

                } else {

                    $sql = "INSERT INTO students
                    (student_name, roll_number, email, password, status)
                    VALUES ($1, $2, $3, $4, 'pending')";

                    $result = pg_query_params(
                        $conn,
                        $sql,
                        [$name, $roll, $email, $hashedPassword]
                    );

                    if ($result) {
                        $message = "Student registration successful! Wait for admin approval.";
                        $messageType = "success";
                    } else {
                        $message = "Registration failed.";
                        $messageType = "error";
                    }
                }

            } elseif ($role === "teacher") {

                $employee = strtoupper(trim($_POST['employee_id'] ?? ''));
                $department = trim($_POST['department'] ?? '');

                $check = pg_query_params(
                    $conn,
                    "SELECT teacher_id FROM teachers
                     WHERE LOWER(email) = $1 OR employee_id = $2",
                    [$email, $employee]
                );

                if ($employee === '' || $department === '' || !$check) {

                    $message = "Please fill all teacher details.";
                    $messageType = "error";

                } elseif (pg_num_rows($check) > 0) {

                    $message = "Email or Employee ID already exists.";
                    $messageType = "error";

                } else {

                    $sql = "INSERT INTO teachers
                    (teacher_name, employee_id, department, email, password, status)
                    VALUES ($1, $2, $3, $4, $5, 'pending')";

                    $result = pg_query_params(
                        $conn,
                        $sql,
                        [$name, $employee, $department, $email, $hashedPassword]
                    );

                    if ($result) {
                        $message = "Teacher registration successful! Wait for admin approval.";
                        $messageType = "success";
                    } else {
                        $message = "Registration failed.";
                        $messageType = "error";
                    }
                }

            } else {
                $message = "Select account type.";
                $messageType = "error";
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>SmartAttend | College Portal</title>

<style>

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: Arial, sans-serif;
}

body {
    background: #f5f7fb;
    color: #202b45;
}

/* HEADER */

.hero {
    background: #172b50;
    color: white;
    padding: 65px 8%;
}

.brand {
    font-size: 30px;
    font-weight: bold;
    margin-bottom: 25px;
}

.brand span {
    color: #6b83ff;
}

.hero h1 {
    font-size: 42px;
    margin-bottom: 20px;
}

.hero p {
    color: #c1cce0;
    font-size: 19px;
    line-height: 1.8;
    max-width: 650px;
}

.stats {
    display: flex;
    gap: 100px;
    margin-top: 45px;
}

.stats h2 {
    font-size: 35px;
}

.stats p {
    font-size: 15px;
}

/* AUTH SECTION */

.auth-section {
    background: white;
    padding: 65px 8%;
    min-height: 600px;
}

.auth-container {
    max-width: 590px;
    margin: auto;
}

.small-title {
    color: #9299a8;
    font-weight: bold;
    letter-spacing: 3px;
    margin-bottom: 25px;
}

.auth-container h1 {
    font-size: 40px;
    margin-bottom: 18px;
}

.subtitle {
    color: #8991a0;
    font-size: 19px;
    line-height: 1.6;
    margin-bottom: 40px;
}

/* TABS */

.tabs {
    display: flex;
    background: #f0f1f6;
    padding: 6px;
    border-radius: 16px;
    margin-bottom: 35px;
}

.tabs button {
    width: 50%;
    padding: 17px;
    border: none;
    background: transparent;
    font-size: 17px;
    font-weight: bold;
    color: #818a9b;
    cursor: pointer;
    border-radius: 12px;
}

.tabs button.active {
    background: white;
    color: #263653;
    box-shadow: 0 3px 12px rgba(0,0,0,.08);
}

/* FORM */

label {
    display: block;
    font-weight: bold;
    color: #566174;
    margin: 23px 0 12px;
}

input, select {
    width: 100%;
    padding: 18px;
    border: 2px solid #e3e6eb;
    border-radius: 13px;
    font-size: 16px;
    outline: none;
    background: white;
}

input:focus, select:focus {
    border-color: #6675e8;
}

.role-buttons {
    display: flex;
    gap: 15px;
    margin: 15px 0 25px;
}

.role-buttons button {
    width: 50%;
    padding: 17px;
    border: 2px solid #e3e6eb;
    border-radius: 13px;
    background: white;
    color: #647084;
    font-size: 16px;
    cursor: pointer;
}

.role-buttons button.selected {
    border-color: #8292eb;
    background: #f2f3ff;
    color: #5264bb;
}

.submit-btn {
    width: 100%;
    padding: 19px;
    background: #5367e8;
    color: white;
    border: none;
    border-radius: 13px;
    font-size: 17px;
    font-weight: bold;
    margin-top: 30px;
    cursor: pointer;
}

.submit-btn:hover {
    background: #4054d0;
}

.message {
    padding: 15px;
    border-radius: 10px;
    margin-bottom: 20px;
    line-height: 1.5;
}

.success {
    background: #dcfce7;
    color: #166534;
}

.error {
    background: #fee2e2;
    color: #991b1b;
}

.footer {
    text-align: center;
    color: #a0a6b1;
    margin-top: 45px;
    font-size: 14px;
}

.hidden {
    display: none;
}

/* RESPONSIVE */

@media(max-width:600px) {

    .hero {
        padding: 40px 25px;
    }

    .hero h1 {
        font-size: 32px;
    }

    .stats {
        gap: 30px;
    }

    .stats h2 {
        font-size: 25px;
    }

    .auth-section {
        padding: 45px 22px;
    }

    .auth-container h1 {
        font-size: 32px;
    }

}

</style>

</head>

<body>

<section class="hero">

    <div class="brand">
        Smart<span>Attend</span>
    </div>

    <h1>College Attendance Management</h1>

    <p>
        A clear, reliable place for students,
        teachers and administrators to manage
        academic attendance.
    </p>

    <div class="stats">

        <div>
            <h2>01</h2>
            <p>One college</p>
        </div>

        <div>
            <h2>03</h2>
            <p>Access roles</p>
        </div>

        <div>
            <h2>100%</h2>
            <p>Clear records</p>
        </div>

    </div>

</section>

<section class="auth-section">

<div class="auth-container">

<div class="small-title" id="smallTitle">
WELCOME BACK
</div>

<h1 id="heading">Sign in to your account</h1>

<p class="subtitle" id="description">
Enter your details to continue to SmartAttend.
</p>

<div class="tabs">

<button type="button"
id="loginTab"
class="<?php echo $activeTab === 'login' ? 'active' : ''; ?>"
onclick="showTab('login')">
Sign in
</button>

<button type="button"
id="registerTab"
class="<?php echo $activeTab === 'register' ? 'active' : ''; ?>"
onclick="showTab('register')">
Register
</button>

</div>

<?php if ($message !== "") { ?>

<div class="message <?php echo $messageType; ?>">
<?php echo htmlspecialchars($message); ?>
</div>

<?php } ?>

<!-- LOGIN FORM -->

<form method="POST" id="loginForm"
class="<?php echo $activeTab === 'login' ? '' : 'hidden'; ?>">

<input type="hidden" name="action" value="login">

<label>Account type</label>

<select name="role" required>
<option value="admin">Admin</option>
<option value="student">Student</option>
<option value="teacher">Teacher</option>
</select>

<label>Email address / Username</label>

<input type="text"
name="email"
placeholder="Enter your email or username"
required>

<label>Password</label>

<input type="password"
name="password"
placeholder="Enter your password"
required>

<button class="submit-btn" type="submit">
Sign in
</button>

</form>

<!-- REGISTER FORM -->

<form method="POST" id="registerForm"
class="<?php echo $activeTab === 'register' ? '' : 'hidden'; ?>">

<input type="hidden" name="action" value="register">

<input type="hidden" name="csrf_token"
value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

<label>Account type</label>

<div class="role-buttons">

<button type="button"
id="studentBtn"
class="selected"
onclick="selectRole('student')">
Student
</button>

<button type="button"
id="teacherBtn"
onclick="selectRole('teacher')">
Teacher
</button>

</div>

<input type="hidden" name="role" id="registerRole" value="student">

<label>Full name</label>

<input type="text"
name="name"
placeholder="Your full name"
required>

<!-- STUDENT FIELDS -->

<div id="studentFields">

<label>Roll number</label>

<input type="text"
name="roll_number"
placeholder="e.g. 250212163">

</div>

<!-- TEACHER FIELDS -->

<div id="teacherFields" class="hidden">

<label>Employee ID</label>

<input type="text"
name="employee_id"
placeholder="e.g. EMP001">

<label>Department</label>

<input type="text"
name="department"
placeholder="e.g. Computer Science">

</div>

<label>Email address</label>

<input type="email"
name="email"
placeholder="name@college.edu"
required>

<label>Password</label>

<input type="password"
name="password"
placeholder="At least 8 characters"
minlength="8"
required>

<label>Confirm Password</label>

<input type="password"
name="confirm_password"
placeholder="Confirm your password"
minlength="8"
required>

<button class="submit-btn" type="submit">
Submit registration
</button>

</form>

<div class="footer">
Protected access · Admin approval required for new accounts
<br><br>
© 2026 SmartAttend. All Rights Reserved.
</div>

</div>

</section>

<script>

function showTab(tab) {

    document.getElementById("loginForm").classList.toggle(
        "hidden", tab !== "login"
    );

    document.getElementById("registerForm").classList.toggle(
        "hidden", tab !== "register"
    );

    document.getElementById("loginTab").classList.toggle(
        "active", tab === "login"
    );

    document.getElementById("registerTab").classList.toggle(
        "active", tab === "register"
    );

    document.getElementById("smallTitle").innerText =
        tab === "login" ? "WELCOME BACK" : "JOIN YOUR CAMPUS";

    document.getElementById("heading").innerText =
        tab === "login" ? "Sign in to your account" : "Create an account";

    document.getElementById("description").innerText =
        tab === "login"
        ? "Enter your details to continue to SmartAttend."
        : "Student and teacher accounts require administrator approval.";
}

function selectRole(role) {

    document.getElementById("registerRole").value = role;

    document.getElementById("studentFields").classList.toggle(
        "hidden", role !== "student"
    );

    document.getElementById("teacherFields").classList.toggle(
        "hidden", role !== "teacher"
    );

    document.getElementById("studentBtn").classList.toggle(
        "selected", role === "student"
    );

    document.getElementById("teacherBtn").classList.toggle(
        "selected", role === "teacher"
    );

    document.querySelector('[name="roll_number"]').required =
        role === "student";

    document.querySelector('[name="employee_id"]').required =
        role === "teacher";

    document.querySelector('[name="department"]').required =
        role === "teacher";
}

<?php if ($activeTab === 'register') { ?>
showTab('register');
<?php } ?>

</script>

</body>
</html>