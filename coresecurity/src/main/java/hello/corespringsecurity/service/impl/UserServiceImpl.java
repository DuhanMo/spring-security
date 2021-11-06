package hello.corespringsecurity.service.impl;

import hello.corespringsecurity.domain.Account;
import hello.corespringsecurity.repository.UserRepository;
import hello.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
