package br.com.atom.mocks;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import br.com.atom.entities.Role;
import br.com.atom.enums.ERole;
import br.com.atom.repositories.RoleRepository;

@Component
public class RoleMock {
	
	@Autowired
	private RoleRepository roleRepository;
	
	@Bean
    private void rolesMock(){
		if (!roleRepository.existsRecords()){
		Role roleAdmin = new Role(null, ERole.ROLE_ADMIN);
		Role roleModerator = new Role(null, ERole.ROLE_MODERATOR);
		Role roleUser = new Role(null, ERole.ROLE_USER);
		roleRepository.save(roleAdmin);
		roleRepository.save(roleModerator);
		roleRepository.save(roleUser);
		}
	}
}
