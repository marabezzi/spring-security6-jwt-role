package br.com.atom.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;

import br.com.atom.entities.RefreshToken;
import br.com.atom.entities.User;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
	  Optional<RefreshToken> findByToken(String token);

	  @Modifying
	  int deleteByUser(User user);
	}