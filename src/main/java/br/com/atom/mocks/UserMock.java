package br.com.atom.mocks;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import br.com.atom.entities.Role;
import br.com.atom.entities.User;
import br.com.atom.enums.ERole;
import br.com.atom.repositories.RoleRepository;
import br.com.atom.repositories.UserRepository;

@Component
public class UserMock {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private RoleRepository roleRepository;
	
	@Bean
    private void usersMock(){
		if (!userRepository.existsRecords()){
			//Senha padrao é 123456
		User userAdmin = new User("admin@atom.com", "$2a$12$mIpL5lS/NdXfaAcnJs559OZNCz8UUZNkbojQCCpoxWetgbxr2Lbw6");
		Set<Role> roles = new HashSet<>();
		Role userRole = roleRepository.findByName(ERole.ROLE_ADMIN)
			      .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
		 roles.add(userRole);
		 userAdmin.setRoles(roles);
	     userRepository.save(userAdmin);
		}
	}
}
