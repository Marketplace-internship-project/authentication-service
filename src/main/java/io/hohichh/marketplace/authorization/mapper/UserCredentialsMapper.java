package io.hohichh.marketplace.authorization.mapper;

import io.hohichh.marketplace.authorization.dto.UserCredentialsCreateDto;
import io.hohichh.marketplace.authorization.dto.UserCredentialsResponseDto;
import io.hohichh.marketplace.authorization.model.UserCredentials;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserCredentialsMapper {


    @Mapping(target = "id", ignore = true)
    @Mapping(target = "passwordHash", ignore = true)
    @Mapping(target = "role", ignore = true)
    UserCredentials toEntity(UserCredentialsCreateDto createDto);


    @Mapping(source = "role.roleName", target = "roleName")
    UserCredentialsResponseDto toResponseDto(UserCredentials entity);
}