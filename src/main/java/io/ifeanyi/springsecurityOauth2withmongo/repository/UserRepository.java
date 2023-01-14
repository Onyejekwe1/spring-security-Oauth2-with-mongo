package io.ifeanyi.springsecurityOauth2withmongo.repository;

import io.ifeanyi.springsecurityOauth2withmongo.document.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByUsername (String username);
    boolean existsByUsername(String username);
}
