<?php
include('../config.php');
session_start();

if(isset($_SESSION['is_login']) && $_SESSION['is_login'] === true){
  header('Location: RequesterProfile.php');
  exit;
}

if(isset($_POST['rSignin'])){
    $rEmail = $_POST['rEmail'];
    $rPassword = $_POST['rPassword'];

    // Validate email format
    if (!filter_var($rEmail, FILTER_VALIDATE_EMAIL)) {
        $msg = '<div class="alert alert-warning mt-2" role="alert">Invalid email format</div>';
    } else {
        // Prepare and bind parameters
        $stmt = $conn->prepare("SELECT r_email, r_password FROM requesterlogin_tb WHERE r_email=?");
        $stmt->bind_param("s", $rEmail);
        $stmt->execute();
        $stmt->store_result();

        if($stmt->num_rows == 1) {
            $stmt->bind_result($dbEmail, $dbPassword);
            $stmt->fetch();
            
            // Compare plain-text password with the stored password
            if($rPassword === $dbPassword){
                $_SESSION['is_login'] = true;
                $_SESSION['rEmail'] = $rEmail;
                // Regenerate session ID
                session_regenerate_id(true);
                header('Location: RequesterProfile.php');
                exit;
            } else {
                $msg = '<div class="alert alert-warning mt-2" role="alert">Incorrect email or password</div>';
            }
        } else {
            $msg = '<div class="alert alert-warning mt-2" role="alert">Incorrect email or password</div>';
        }
        $stmt->close();
    }
}
?>


<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login</title>
  <link rel="shortcut icon" type="image/png" href="../images/favi.png">
  <link href="https://fonts.googleapis.com/css?family=Open+Sans:400,700" rel="stylesheet">
  <link rel="stylesheet" href="style.css">
</head>
<body class="align">
  <div class="grid">
    <h1 align="center">Login</h1><br>
    <form action="" method="POST" class="form login">
      <div class="form__field">
        <label for="login__username"><svg class="icon"><use xlink:href="#email"></use></svg><span class="hidden">Email</span></label>
        <input id="login__username" type="email" name="rEmail" class="form__input" placeholder="Email" required>
      </div>
      <div class="form__field">
        <label for="login__password"><svg class="icon"><use xlink:href="#lock"></use></svg><span class="hidden">Password</span></label>
        <input id="login__password" type="password" name="rPassword" class="form__input" placeholder="Password" required>
      </div>
      <div class="form__field">
        <input type="submit" value="Sign In" name="rSignin">
      </div>
      <?php if(isset($msg)) {echo $msg; } ?>
    </form>
    <p class="text--center">Not a member? <a href="register.php">Sign up now</a> <svg class="icon"><use xlink:href="assets/images/icons.svg#arrow-right"></use></svg></p>
  </div>
  <svg xmlns="http://www.w3.org/2000/svg" class="icons"><symbol id="arrow-right" viewBox="0 0 1792 1792"><path d="M1600 960q0 54-37 91l-651 651q-39 37-91 37-51 0-90-37l-75-75q-38-38-38-91t38-91l293-293H245q-52 0-84.5-37.5T128 1024V896q0-53 32.5-90.5T245 768h704L656 474q-38-36-38-90t38-90l75-75q38-38 90-38 53 0 91 38l651 651q37 35 37 90z"/></symbol>
  <symbol id="email" viewBox="0 0 512 512"><path d="M48 64C21.5 64 0 85.5 0 112c0 15.1 7.1 29.3 19.2 38.4L236.8 313.6c11.4 8.5 27 8.5 38.4 0L492.8 150.4c12.1-9.1 19.2-23.3 19.2-38.4c0-26.5-21.5-48-48-48H48zM0 176V384c0 35.3 28.7 64 64 64H448c35.3 0 64-28.7 64-64V176L294.4 339.2c-22.8 17.1-54 17.1-76.8 0L0 176z"/></symbol>
  <symbol id="lock" viewBox="0 0 1792 1792"><path d="M640 768h512V576q0-106-75-181t-181-75-181 75-75 181v192zm832 96v576q0 40-28 68t-68 28H416q-40 0-68-28t-28-68V864q0-40 28-68t68-28h32V576q0-184 132-316t316-132 316 132 132 316v192h32q40 0 68 28t28 68z"/></symbol>
  <symbol id="user" viewBox="0 0 1792 1792"><path d="M1600 1405q0 120-73 189.5t-194 69.5H459q-121 0-194-69.5T192 1405q0-53 3.5-103.5t14-109T236 1084t43-97.5 62-81 85.5-53.5T538 832q9 0 42 21.5t74.5 48 108 48T896 971t133.5-21.5 108-48 74.5-48 42-21.5q61 0 111.5 20t85.5 53.5 62 81 43 97.5 26.5 108.5 14 109 3.5 103.5zm-320-893q0 159-112.5 271.5T896 896 624.5 783.5 512 512t112.5-271.5T896 128t271.5 112.5T1280 512z"/></symbol></svg>
</body>
</html>
