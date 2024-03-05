package br.com.atom.services;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import br.com.atom.entities.User;
import br.com.atom.repositories.UserRepository;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  @Autowired
  UserRepository userRepository;



  @Override
  @Transactional
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
	  User user = userRepository.findByEmail(email)
		        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + email));

		    return UserDetailsImpl.build(user);
  }
}