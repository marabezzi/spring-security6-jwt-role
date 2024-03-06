package br.com.atom.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.atom.entities.RefreshToken;
import br.com.atom.entities.Role;
import br.com.atom.entities.User;
import br.com.atom.enums.ERole;
import br.com.atom.jwt.JWTUtils;
import br.com.atom.jwt.exception.TokenRefreshException;
import br.com.atom.payload.request.LoginRequest;
import br.com.atom.payload.request.SignupRequest;
import br.com.atom.payload.response.JwtResponse;
import br.com.atom.payload.response.MessageResponse;
import br.com.atom.payload.response.UserInfoResponse;
import br.com.atom.repositories.RoleRepository;
import br.com.atom.repositories.UserRepository;
import br.com.atom.services.RefreshTokenService;
import br.com.atom.services.UserDetailsImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
	
	 @Autowired
	  AuthenticationManager authenticationManager;

	  @Autowired
	  UserRepository userRepository;

	  @Autowired
	  RoleRepository roleRepository;

	  @Autowired
	  PasswordEncoder encoder;

	  @Autowired
	  JWTUtils jwtUtils;
	  
	  @Autowired
	  RefreshTokenService refreshTokenService;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

	    Authentication authentication = authenticationManager
	        .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

	    SecurityContextHolder.getContext().setAuthentication(authentication);

	    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
	    
	    ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
	    
	    List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
	        .collect(Collectors.toList());

	    RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
	    
	    ResponseCookie jwtRefreshCookie = jwtUtils.generateRefreshJwtCookie(refreshToken.getToken());

	    /*return ResponseEntity.ok(new JwtResponse(jwt, refreshToken.getToken(), userDetails.getId(),
	        userDetails.getUsername(), userDetails.getEmail(), roles));*/
	 
	    return ResponseEntity.ok()
	              .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
	              .header(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString())
	              .body(new UserInfoResponse(userDetails.getId(),
	                                        // userDetails.getUsername(),
	                                         userDetails.getEmail(),
	                                         roles));
	  }

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
	/*	System.out.println("User: " + signUpRequest.getEmail());
		System.out.println("Password: " + signUpRequest.getPassword());
		System.out.println("Role: " + signUpRequest.getRole());*/
		
	 if (userRepository.existsByEmail(signUpRequest.getEmail())) {
		 return ResponseEntity
				 .badRequest()
				 .body(new MessageResponse("Error: Username is already taken!"));
	}
	 
	 // Create new user's account
	 User user = new User(signUpRequest.getEmail(),
			              encoder.encode(signUpRequest.getPassword()));
	 
	 Set<String> strRoles = signUpRequest.getRole();
	 Set<Role> roles = new HashSet<>();
	 
	 if (strRoles == null) {
	      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
	          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
	      roles.add(userRole);
	    //  System.out.println("P A S S O U");
	    } else {
	      strRoles.forEach(role -> {
	        switch (role) {
	        case "admin":
	          Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
	              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
	          roles.add(adminRole);

	          break;
	        case "mod":
	          Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
	              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
	          roles.add(modRole);

	          break;
	        default:
	          Role userRole = roleRepository.findByName(ERole.ROLE_USER)
	              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
	          roles.add(userRole);
	        }
	      });
	    }
	 user.setRoles(roles);
     userRepository.save(user);
	 
	 return ResponseEntity.ok(new MessageResponse("User registred successfully!"));
 }

	  @GetMapping("/all")
	  public String allAccess() {
	    return "Public Content.";
	  }
	  
	  @PostMapping("/signout")
	  public ResponseEntity<?> logoutUser() {
	    Object principle = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
	    if (principle.toString() != "anonymousUser") {      
	      Long userId = ((UserDetailsImpl) principle).getId();
	      refreshTokenService.deleteByUserId(userId);
	    }
	    
	    ResponseCookie jwtCookie = jwtUtils.getCleanJwtCookie();
	    ResponseCookie jwtRefreshCookie = jwtUtils.getCleanJwtRefreshCookie();

	    return ResponseEntity.ok()
	        .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
	        .header(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString())
	        .body(new MessageResponse("You've been signed out!"));
	  }

	  @PostMapping("/refreshtoken")
	  public ResponseEntity<?> refreshtoken(HttpServletRequest request) {
	    String refreshToken = jwtUtils.getJwtRefreshFromCookies(request);
	    
	    if ((refreshToken != null) && (refreshToken.length() > 0)) {
	      return refreshTokenService.findByToken(refreshToken)
	          .map(refreshTokenService::verifyExpiration)
	          .map(RefreshToken::getUser)
	          .map(user -> {
	            ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(user);
	            
	            return ResponseEntity.ok()
	                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
	                .body(new MessageResponse("Token is refreshed successfully!"));
	          })
	          .orElseThrow(() -> new TokenRefreshException(refreshToken,
	              "Refresh token is not in database!"));
	    }
	    
	    return ResponseEntity.badRequest().body(new MessageResponse("Refresh Token is empty!"));
	  }
}
