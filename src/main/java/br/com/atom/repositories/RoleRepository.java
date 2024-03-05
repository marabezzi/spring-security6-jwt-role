package br.com.atom.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import br.com.atom.entities.Role;
import br.com.atom.enums.ERole;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer>{

	Optional<Role> findByName(ERole name);
	
	@Query("SELECT EXISTS (SELECT 1 FROM #{#entityName})")
	Boolean existsRecords();
}
