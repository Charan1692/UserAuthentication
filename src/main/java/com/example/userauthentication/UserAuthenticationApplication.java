package com.example.userauthentication;

import com.example.utils.AuthUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.jdbc.core.JdbcTemplate;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.RowMapper;

@SpringBootApplication
@RestController
public class UserAuthenticationApplication {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    public static void main(String[] args) {
        SpringApplication.run(UserAuthenticationApplication.class, args);
    }

    @GetMapping("/users")
    public String getUsers() throws Exception {
        AuthUtils authUtils = new AuthUtils();
        String sqlSelect = "SELECT * FROM Users";
        List<User> listContact = jdbcTemplate.query(sqlSelect, new RowMapper<User>() {
            public User mapRow(ResultSet result, int rowNum) throws SQLException {
                User user = new User();
                user.setUserName(result.getString("user_name"));
                String decryptPwd = authUtils.decrypt(result.getString("password"), AuthUtils.SECRET_KEY);
                user.setPassword(decryptPwd);
                return user;
            }
        });

        String res = "[";
        for (User aContact : listContact) {
            res += aContact.toString();
        }
        res += "]";
        return res;
    }

    @PostMapping("/auth")
    public String authUser(@RequestParam String userName, @RequestParam String password) {
        AuthUtils authUtils = new AuthUtils();

        //Check in DB
        String sqlSelect = "SELECT * FROM Users where user_name=?";
        List<User> listContact = jdbcTemplate.query(sqlSelect, new Object[]{userName}, new RowMapper<User>() {
            public User mapRow(ResultSet result, int rowNum) throws SQLException {
                User user = new User();
                user.setUserName(result.getString("user_name"));
                user.setPassword(result.getString("password"));
                return user;
            }
        });

        String response = "Not a Registered User";
        Boolean isValidUser = Boolean.FALSE;
        if(listContact.size() > 0) {
            response = "InValid Password";

            // Encrypting the request password
            String encryptPwd = authUtils.encrypt(password, AuthUtils.SECRET_KEY);

            // Checking password is valid or not
            String dbPwd = listContact.get(0).getPassword();
            boolean isValidPwd = dbPwd.equals(encryptPwd);

            // If valid Generating Session Id
            if(isValidPwd) {
                isValidUser = Boolean.TRUE;
                String sessionID = UUID.randomUUID().toString();
                response = String.format("Valid User & Session Id : %s", sessionID);
            }
        }

        //Log the Failure
        String device_type = "Web";
        if(!isValidUser) {
            String failInsertQuery = "INSERT INTO FAILURE_LOGS (user_name, reason, device_type) VALUES (?, ?, ?)";
            int row = jdbcTemplate.update(failInsertQuery, new Object[]{userName, response, device_type});
            System.out.println(" Failure Reason Logged :row: " + row);
        } else {
            String sucInsertQuery = "INSERT INTO SUCCESS_LOGS (user_name, device_type) VALUES (?, ?)";
            int row = jdbcTemplate.update(sucInsertQuery, new Object[]{userName, device_type});
            System.out.println("SUCCESS Logged :row: " + row);
        }

        return response;
    }

    @PostMapping("/dumpTempData")
    public String dumpUsersData() {
        String insert_query = "INSERT INTO Users (user_name, password) VALUES (?, ?)";
        AuthUtils authUtils = new AuthUtils();
        List<User> usersList = authUtils.getDumpUsersData();

        jdbcTemplate.batchUpdate(insert_query, new BatchPreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement pStmt, int j) throws SQLException {
                User user = usersList.get(j);
                pStmt.setString(1, user.getUserName());
                pStmt.setString(2, user.getPassword());
            }

            @Override
            public int getBatchSize() {
                return usersList.size();
            }
        });
        return "Inserted Temp Users Data";
    }

}
